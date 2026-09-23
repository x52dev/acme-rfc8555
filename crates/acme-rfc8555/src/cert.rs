use std::io::{BufReader, Cursor};

use der::{
    asn1::Ia5String,
    time::{OffsetDateTime, PrimitiveDateTime},
    Decode as _,
};
use eyre::{eyre, WrapErr as _};
use p256::elliptic_curve::Generate as _;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rustls_pki_types::{pem::SectionKind, CertificateDer};
use x509_cert::{
    builder::Builder,
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
    request::RequestBuilder as CsrBuilder,
};
use zeroize::Zeroizing;

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> PrivateKey {
    PrivateKey {
        inner: ecdsa::SigningKey::generate_from_rng(&mut rand::rng()),
    }
}

/// A P-256 private key for certificate issuance.
///
/// Generate a key with [`create_p256_key`] or import one with [`Self::from_pkcs8_pem`].
#[derive(Clone)]
pub struct PrivateKey {
    inner: p256::ecdsa::SigningKey,
}

impl PrivateKey {
    /// Imports a P-256 private key from PKCS#8 PEM.
    pub fn from_pkcs8_pem(pem: &str) -> eyre::Result<Self> {
        let inner = p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
            .context("Failed to read P-256 private key PEM")?;

        Ok(Self { inner })
    }

    /// Exports the private key as PKCS#8 PEM with LF line endings.
    ///
    /// The returned string is zeroized when dropped.
    pub fn to_pkcs8_pem(&self) -> eyre::Result<Zeroizing<String>> {
        self.inner
            .to_pkcs8_pem(pem::LineEnding::LF)
            .context("Failed to encode P-256 private key PEM")
    }

    pub(crate) fn into_signing_key(self) -> p256::ecdsa::SigningKey {
        self.inner
    }
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

    let mut csr = CsrBuilder::new(subject).unwrap();

    if domains.len() > 1 {
        csr.add_extension(&SubjectAltName(
            domains[0..]
                .iter()
                .map(|domain| GeneralName::DnsName(Ia5String::new(domain).unwrap()))
                .collect(),
        ))
        .unwrap();
    }

    csr.build::<_, p256::ecdsa::DerSignature>(signer)
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

    /// Loads a saved P-256 private key and certificate chain from PEM strings.
    ///
    /// The key must use PKCS#8 encoding. This method checks that the key and certificate can be
    /// decoded. It does not check that they match, that the certificate is trusted, or that it is
    /// within its validity period.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain has no certificates, a certificate cannot be decoded, or the
    /// P-256 private key cannot be decoded.
    pub fn parse(private_key_pem: Zeroizing<String>, certificate: String) -> eyre::Result<Self> {
        let mut has_certificate = false;

        for section in
            rustls_pki_types::pem::ReadIter::new(&mut BufReader::new(Cursor::new(&certificate)))
        {
            let (kind, der) = section?;

            if kind != SectionKind::Certificate {
                return Err(eyre!("unexpected PEM section in certificate chain"));
            }

            x509_cert::Certificate::from_der(&der)?;
            has_certificate = true;
        }

        if !has_certificate {
            return Err(eyre!("no certificates in chain"));
        }

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

        // Use (SectionKind, Vec<u8>) to extract all PEM sections, then filter for certificates
        let certs = rustls_pki_types::pem::ReadIter::new(&mut rdr)
            .filter_map(|res| match res {
                Ok((SectionKind::Certificate, der)) => Some(CertificateDer::from(der)),
                _ => None,
            })
            .collect::<Vec<_>>();

        // Convert to Vec<Vec<u8>>
        let certs = certs
            .into_iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect();

        Ok(certs)
    }

    /// Inspect the certificate to count the number of (whole) valid days left.
    ///
    /// It's up to the ACME API provider to decide how long an issued certificate is valid.
    /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
    /// issued cert, since it counts _whole_ days.
    ///
    /// It is possible to get negative days for an expired certificate.
    pub fn valid_days_left(&self) -> eyre::Result<i64> {
        let cert_chain = self.certificate_chain()?;
        let cert_ee = cert_chain
            .first() // EE cert is first
            .ok_or_else(|| eyre!("no certificates in chain"))?;

        let cert = x509_cert::Certificate::from_der(cert_ee)?;

        let not_after = cert.tbs_certificate().validity().not_after.to_date_time();
        // TODO: justify assume_utc
        let not_after = PrimitiveDateTime::try_from(not_after).unwrap().assume_utc();

        let diff = not_after - OffsetDateTime::now_utc();

        Ok(diff.whole_days())
    }
}
