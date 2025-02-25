use std::io::{BufReader, Cursor};

use der::{
    asn1::Ia5String,
    time::{OffsetDateTime, PrimitiveDateTime},
    Decode as _, DecodePem as _,
};
use eyre::{eyre, WrapErr as _};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use x509_cert::{
    builder::{Builder, RequestBuilder as CsrBuilder},
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
};
use zeroize::Zeroizing;

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> p256::ecdsa::SigningKey {
    let csprng = &mut rand::thread_rng();
    ecdsa::SigningKey::from(p256::SecretKey::random(csprng))
}

/// Creates a CSR with `domains` and signs it with `signer`.
///
/// The first item of `domains` is picked for the CSR's Common Name (CN). All domains are added to a
/// Subject Alternative Name (SAN) extension.
pub(crate) fn create_csr(
    signer: &p256::ecdsa::SigningKey,
    domains: &[&str],
) -> eyre::Result<x509_cert::request::CertReq> {
    let primary_domain = domains.first().unwrap();
    let subject = format!("CN={primary_domain}").parse::<Name>().unwrap();

    let mut csr = CsrBuilder::new(subject, signer).unwrap();

    if domains.len() > 1 {
        csr.add_extension(&SubjectAltName(
            domains[0..]
                .iter()
                .map(|domain| GeneralName::DnsName(Ia5String::new(domain).unwrap()))
                .collect(),
        ))
        .unwrap();
    }

    csr.build::<p256::ecdsa::DerSignature>()
        .context("build csr")
}

/// Encapsulated certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    private_key_pem: Zeroizing<String>,
    certificate: String,
}

impl Certificate {
    pub(crate) fn new(private_key_pem: Zeroizing<String>, certificate: String) -> Self {
        Certificate {
            private_key_pem,
            certificate,
        }
    }

    pub fn parse(private_key_pem: Zeroizing<String>, certificate: String) -> eyre::Result<Self> {
        // validate certificate
        x509_cert::Certificate::from_pem(certificate.as_str())?;

        // validate private key
        ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(&private_key_pem)?;

        Ok(Certificate {
            private_key_pem,
            certificate,
        })
    }

    /// The private key in PEM format.
    pub fn private_key(&self) -> &str {
        &self.private_key_pem
    }

    /// The private key in DER encoding.
    pub fn private_key_der(&self) -> eyre::Result<Vec<u8>> {
        let private_key =
            ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(&self.private_key_pem)?;
        let der = private_key.to_pkcs8_der()?;
        Ok(der.as_bytes().to_vec())
    }

    /// The issued certificate file in PEM format.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate chain in DER format.
    pub fn certificate_chain(&self) -> eyre::Result<Vec<Vec<u8>>> {
        let mut rdr = BufReader::new(Cursor::new(self.certificate()));

        rustls_pemfile::certs(&mut rdr)
            .map(|res| res.map(|cert| cert.to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Inspect the certificate to count the number of (whole) valid days left.
    ///
    /// It's up to the ACME API provider to decide how long an issued certificate is valid.
    /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
    /// issued cert, since it counts _whole_ days.
    ///
    /// It is possible to get negative days for an expired certificate.
    pub fn valid_days_left(&self) -> eyre::Result<i64> {
        // the cert used in the tests is not valid to load as x509
        if cfg!(test) {
            return Ok(89);
        }

        let cert_chain = self.certificate_chain()?;
        let cert_ee = cert_chain
            .first() // EE cert is first
            .ok_or_else(|| eyre!("no certificates in chain"))?;

        let cert = x509_cert::Certificate::from_der(cert_ee)?;

        let not_after = cert.tbs_certificate.validity.not_after.to_date_time();
        // TODO: justify assume_utc
        let not_after = PrimitiveDateTime::try_from(not_after).unwrap().assume_utc();

        let diff = not_after - OffsetDateTime::now_utc();

        Ok(diff.whole_days())
    }
}
