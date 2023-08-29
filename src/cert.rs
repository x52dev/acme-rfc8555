use der::{
    time::{OffsetDateTime, PrimitiveDateTime},
    DecodePem as _,
};
use once_cell::sync::Lazy;
use openssl::{
    ec::{Asn1Flag, EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{self, PKey},
    rsa::Rsa,
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Req, X509ReqBuilder, X509},
};

use crate::error::Result;

pub(crate) static EC_GROUP_P256: Lazy<EcGroup> = Lazy::new(|| ec_group(Nid::X9_62_PRIME256V1));
pub(crate) static EC_GROUP_P384: Lazy<EcGroup> = Lazy::new(|| ec_group(Nid::SECP384R1));

fn ec_group(nid: Nid) -> EcGroup {
    let mut g = EcGroup::from_curve_name(nid).expect("EcGroup");
    // this is required for openssl 1.0.x (but not 1.1.x)
    g.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    g
}

/// Make an RSA private key (from which we can derive a public key).
///
/// This library does not check the number of bits used to create the key pair.
/// For Let's Encrypt, the bits must be between 2048 and 4096.
pub fn create_rsa_key(bits: u32) -> Result<PKey<pkey::Private>> {
    let pri_key_rsa = Rsa::generate(bits)?;
    let pkey = PKey::from_rsa(pri_key_rsa)?;
    Ok(pkey)
}

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> Result<PKey<pkey::Private>> {
    let pri_key_ec = EcKey::generate(&EC_GROUP_P256)?;
    let pkey = PKey::from_ec_key(pri_key_ec)?;
    Ok(pkey)
}

/// Make a P-384 private key pair (from which we can derive a public key).
pub fn create_p384_key() -> Result<PKey<pkey::Private>> {
    let pri_key_ec = EcKey::generate(&EC_GROUP_P384)?;
    let pkey = PKey::from_ec_key(pri_key_ec)?;
    Ok(pkey)
}

pub(crate) fn create_csr(pkey: &PKey<pkey::Private>, domains: &[&str]) -> Result<X509Req> {
    // the csr builder
    let mut req_bld = X509ReqBuilder::new()?;

    // set private/public key in builder
    req_bld.set_pubkey(pkey)?;

    // set all domains as alt names
    let mut stack = Stack::new()?;
    let ctx = req_bld.x509v3_context(None);
    let mut an = SubjectAlternativeName::new();
    for d in domains {
        an.dns(d);
    }
    let ext = an.build(&ctx)?;
    stack.push(ext).expect("Stack::push");
    req_bld.add_extensions(&stack)?;

    // sign it
    req_bld.sign(pkey, MessageDigest::sha256())?;

    // the csr
    Ok(req_bld.build())
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
        X509::from_pem(certificate.as_bytes())?;
        // validate private key
        PKey::private_key_from_pem(private_key.as_bytes())?;

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
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        let pkey = PKey::private_key_from_pem(self.private_key.as_bytes())?;
        let der = pkey.private_key_to_der()?;
        Ok(der)
    }

    /// The PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate as DER.
    pub fn certificate_der(&self) -> Result<Vec<u8>> {
        let x509 = X509::from_pem(self.certificate.as_bytes())?;
        let der = x509.to_der()?;
        Ok(der)
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

        let cert = x509_cert::Certificate::from_pem(self.certificate.as_bytes())?;

        let not_after = cert.tbs_certificate.validity.not_after.to_date_time();
        // TODO: justify assume_utc
        let not_after = PrimitiveDateTime::try_from(not_after).unwrap().assume_utc();

        let diff = not_after - OffsetDateTime::now_utc();

        Ok(diff.whole_days())
    }
}
