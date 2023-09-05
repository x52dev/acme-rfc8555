use eyre::WrapErr as _;
use pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub(crate) struct AcmeKey {
    /// Private key for ACME API interactions.
    private_key: p256::ecdsa::SigningKey,

    /// Key ID that is set once an ACME account is created.
    key_id: Option<String>,
}

impl AcmeKey {
    /// Constructs new ACME key with random private key.
    pub(crate) fn new() -> AcmeKey {
        Self::from_key(crate::create_p256_key())
    }

    /// Constructs new ACME key from PEM-encoded private key.
    ///
    /// No key ID is set.
    pub(crate) fn from_pem(pem: &str) -> eyre::Result<AcmeKey> {
        let private_key = ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(pem)
            .context("Failed to read PEM")?;

        Ok(Self::from_key(private_key))
    }

    /// Constructs new ACME key from private key.
    ///
    /// No key ID is set.
    fn from_key(private_key: p256::ecdsa::SigningKey) -> AcmeKey {
        AcmeKey {
            private_key,
            key_id: None,
        }
    }

    /// Returns PEM-encoded private key.
    pub(crate) fn to_pem(&self) -> eyre::Result<Zeroizing<String>> {
        self.private_key
            .to_pkcs8_pem(pem::LineEnding::LF)
            .context("private_key_to_pem")
    }

    /// Returns signing key.
    pub(crate) fn signing_key(&self) -> &p256::ecdsa::SigningKey {
        &self.private_key
    }

    /// Return key ID.
    ///
    /// # Panics
    ///
    /// Panics if key ID is not set.
    pub(crate) fn key_id(&self) -> &str {
        self.key_id.as_ref().unwrap()
    }

    /// Sets key ID.
    ///
    /// Overwrites any previously set value.
    pub(crate) fn set_key_id(&mut self, kid: String) {
        self.key_id = Some(kid)
    }
}
