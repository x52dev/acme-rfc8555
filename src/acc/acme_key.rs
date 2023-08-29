use anyhow::Context as _;
use pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use zeroize::Zeroizing;

use crate::error::Result;

#[derive(Clone, Debug)]
pub(crate) struct AcmeKey {
    signing_key: p256::ecdsa::SigningKey,

    /// Set once we contacted the ACME API to figure out the key ID.
    key_id: Option<String>,
}

impl AcmeKey {
    pub(crate) fn new() -> AcmeKey {
        Self::from_key(crate::create_p256_key())
    }

    pub(crate) fn from_pem(pem: &str) -> Result<AcmeKey> {
        let pri_key = ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(pem)
            .context("Failed to read PEM")?;
        Ok(Self::from_key(pri_key))
    }

    fn from_key(signing_key: p256::ecdsa::SigningKey) -> AcmeKey {
        AcmeKey {
            signing_key,
            key_id: None,
        }
    }

    pub(crate) fn to_pem(&self) -> Result<Zeroizing<String>> {
        self.signing_key
            .to_pkcs8_pem(pem::LineEnding::LF)
            .context("private_key_to_pem")
    }

    pub(crate) fn signing_key(&self) -> &p256::ecdsa::SigningKey {
        &self.signing_key
    }

    pub(crate) fn key_id(&self) -> &str {
        self.key_id.as_ref().unwrap()
    }

    pub(crate) fn set_key_id(&mut self, kid: String) {
        self.key_id = Some(kid)
    }
}
