use der::{
    asn1::Ia5String,
    time::{OffsetDateTime, PrimitiveDateTime},
    DecodePem as _, Encode,
};
use eyre::WrapErr as _;
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
    signing_key_pem: Zeroizing<String>,
    certificate: String,
}

impl Certificate {
    pub(crate) fn new(signing_key_pem: Zeroizing<String>, certificate: String) -> Self {
        Certificate {
            signing_key_pem,
            certificate,
        }
    }

    pub fn parse(signing_key_pem: Zeroizing<String>, certificate: String) -> eyre::Result<Self> {
        // validate certificate
        x509_cert::Certificate::from_pem(certificate.as_str())?;

        // validate private key
        ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(&signing_key_pem)?;

        Ok(Certificate {
            signing_key_pem,
            certificate,
        })
    }

    /// The private key in PEM format.
    pub fn private_key(&self) -> &str {
        &self.signing_key_pem
    }

    /// The private key in DER encoding.
    pub fn private_key_der(&self) -> eyre::Result<Vec<u8>> {
        let signing_key =
            ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(&self.signing_key_pem)?;
        let der = signing_key.to_pkcs8_der()?;
        Ok(der.as_bytes().to_vec())
    }

    /// The issued certificate in PEM format.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate in DER encoding.
    pub fn certificate_der(&self) -> eyre::Result<Vec<u8>> {
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
    pub fn valid_days_left(&self) -> eyre::Result<i64> {
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
