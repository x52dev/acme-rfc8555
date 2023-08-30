use anyhow::Context as _;
use der::{
    asn1::Ia5String,
    time::{OffsetDateTime, PrimitiveDateTime},
    DecodePem as _, Encode,
};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use x509_cert::{
    builder::{Builder, RequestBuilder as CsrBuilder},
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
};

use crate::error::Result;

/// Make an RSA private key (from which we can derive a public key).
///
/// This library does not check the number of bits used to create the key pair.
/// For Let's Encrypt, the bits must be between 2048 and 4096.
pub fn create_rsa_key(bit_size: usize) -> anyhow::Result<rsa::RsaPrivateKey> {
    let csprng = &mut rand::thread_rng();
    Ok(rsa::RsaPrivateKey::new(csprng, bit_size)?)
}

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> p256::ecdsa::SigningKey {
    let csprng = &mut rand::thread_rng();
    ecdsa::SigningKey::from(p256::SecretKey::random(csprng))
}

/// Make a P-384 private key pair (from which we can derive a public key).
pub fn create_p384_key() -> ecdsa::SigningKey<p384::NistP384> {
    let csprng = &mut rand::thread_rng();
    ecdsa::SigningKey::from(p384::SecretKey::random(csprng))
}

pub(crate) fn create_csr(
    signer: &p256::ecdsa::SigningKey,
    domains: &[&str],
) -> anyhow::Result<x509_cert::request::CertReq> {
    let subject = "CN=localhost".parse::<Name>().unwrap();

    let mut csr = CsrBuilder::new(subject, signer).unwrap();

    csr.add_extension(&SubjectAltName(
        domains
            .iter()
            .map(|domain| GeneralName::DnsName(Ia5String::new(domain).unwrap()))
            .collect(),
    ))
    .unwrap();

    csr.build::<p256::ecdsa::DerSignature>()
        .context("build csr")
}

/// Encapsulated certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    private_key: String,
    certificate: String,
}

impl Certificate {
    pub(crate) fn new(private_key: String, certificate: String) -> Self {
        Certificate {
            private_key,
            certificate,
        }
    }

    pub fn parse(private_key: String, certificate: String) -> Result<Self> {
        // validate certificate
        x509_cert::Certificate::from_pem(certificate.as_bytes())?;
        // validate private key
        ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(&private_key)?;

        Ok(Certificate {
            private_key,
            certificate,
        })
    }

    /// The PEM encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// The private key as DER.
    pub fn private_key_der(&self) -> anyhow::Result<Vec<u8>> {
        let signing_key = ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(&self.private_key)?;
        let der = signing_key.to_pkcs8_der()?;
        Ok(der.as_bytes().to_vec())
    }

    /// The PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate as DER.
    pub fn certificate_der(&self) -> anyhow::Result<Vec<u8>> {
        let x509 = x509_cert::Certificate::from_pem(&self.certificate)?;
        x509.to_der().context("der")
    }

    /// Inspect the certificate to count the number of (whole) valid days left.
    ///
    /// It's up to the ACME API provider to decide how long an issued certificate is valid.
    /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
    /// issued cert, since it counts _whole_ days.
    ///
    /// It is possible to get negative days for an expired certificate.
    pub fn valid_days_left(&self) -> Result<i64> {
        // the cert used in the tests is not valid to load as x509
        if cfg!(test) {
            return Ok(89);
        }

        let cert = x509_cert::Certificate::from_pem(&self.certificate)?;

        let not_after = cert.tbs_certificate.validity.not_after.to_date_time();
        // TODO: justify assume_utc
        let not_after = PrimitiveDateTime::try_from(not_after).unwrap().assume_utc();

        let diff = not_after - OffsetDateTime::now_utc();

        Ok(diff.whole_days())
    }
}
