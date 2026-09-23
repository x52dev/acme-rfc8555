use std::sync::Arc;

use crate::{
    acc::AcmeKey,
    api,
    req::{req_expect_header, req_get, req_handle_error},
    trans::{NoncePool, Transport},
    Account,
};

const LETSENCRYPT_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETSENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Enumeration of known ACME API directories.
#[derive(Debug, Clone)]
pub enum DirectoryUrl<'a> {
    /// The main Let's Encrypt directory.
    ///
    /// Not appropriate for testing / development.
    LetsEncrypt,

    /// The staging Let's Encrypt directory.
    ///
    /// Use for testing and development. Doesn't issue "valid" certificates. The root signing
    /// certificate is not supposed to be in any trust chains.
    LetsEncryptStaging,

    /// Provide an arbitrary directory URL to connect to.
    Other(&'a str),
}

impl DirectoryUrl<'_> {
    fn to_url(&self) -> &str {
        match self {
            DirectoryUrl::LetsEncrypt => LETSENCRYPT_URL,
            DirectoryUrl::LetsEncryptStaging => LETSENCRYPT_STAGING_URL,
            DirectoryUrl::Other(url) => url,
        }
    }
}

/// Entry point for accessing an ACME API.
#[derive(Clone)]
pub struct Directory {
    nonce_pool: Arc<NoncePool>,
    api_directory: api::Directory,
}

impl Directory {
    /// Fetches the provider's directory and prepares a pool of request nonces.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not a valid directory object.
    pub async fn fetch(url: DirectoryUrl<'_>) -> eyre::Result<Directory> {
        let res = req_handle_error(req_get(url.to_url()).await).await?;
        let api_directory = res.json::<api::Directory>().await?;
        let nonce_pool = Arc::new(NoncePool::new(&api_directory.new_nonce));

        Ok(Directory {
            nonce_pool,
            api_directory,
        })
    }

    /// Registers an account with a newly generated P-256 account key.
    ///
    /// `contact` contains contact URIs, such as `mailto:admin@example.com`. Pass `None` to omit
    /// contact details. This request agrees to the provider's terms of service.
    ///
    /// Save the key from [`Account::acme_private_key_pem`] to load this account later.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the provider rejects registration, or the response
    /// is missing required account data.
    pub async fn register_account(&self, contact: Option<Vec<String>>) -> eyre::Result<Account> {
        let acme_key = AcmeKey::new();
        self.upsert_account(acme_key, contact).await
    }

    /// Loads an account using its P-256 PKCS#8 PEM key, or registers it if it does not exist.
    ///
    /// `contact` contains contact URIs for registration. This request agrees to the provider's
    /// terms of service. Use [`Self::load_existing_account`] to avoid registering a new account.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be decoded, the request fails, or the provider returns
    /// an error or an invalid account response.
    pub async fn load_account(
        &self,
        private_key_pem: &str,
        contact: Option<Vec<String>>,
    ) -> eyre::Result<Account> {
        let acme_key = AcmeKey::from_pem(private_key_pem)?;
        self.upsert_account(acme_key, contact).await
    }

    /// Loads an existing account using its P-256 PKCS#8 PEM key.
    ///
    /// The key must identify an account at this directory's provider. This method does not
    /// register an account or send agreement to the terms of service.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot be decoded, no account exists for the key, the request
    /// fails, or the response is missing required account data.
    pub async fn load_existing_account(&self, private_key_pem: &str) -> eyre::Result<Account> {
        let acme_key = AcmeKey::from_pem(private_key_pem)?;

        let acc = api::Account {
            only_return_existing: Some(true),
            ..Default::default()
        };

        let mut transport = Transport::new(Arc::clone(&self.nonce_pool), acme_key);

        let res = transport
            .call_jwk(&self.api_directory.new_account, &acc)
            .await?;

        let kid = req_expect_header(&res, "location")?;
        log::debug!("Key ID is: {kid}");
        let api_account = res.json::<api::Account>().await?;

        // fill in the server returned key ID
        transport.set_key_id(kid);

        Ok(Account::new(
            transport,
            api_account,
            self.api_directory.clone(),
        ))
    }

    async fn upsert_account(
        &self,
        acme_key: AcmeKey,
        contact: Option<Vec<String>>,
    ) -> eyre::Result<Account> {
        // Prepare making a call to newAccount. This is fine to do both for new
        // keys and existing. For existing the spec says to return a 200 with
        // the Location header set to the key ID (kid).
        let acc = api::Account {
            // TODO: ensure email contains no hfields or more than one addr-spec in the to component
            // see https://datatracker.ietf.org/doc/html/rfc8555#section-7.3
            contact,
            terms_of_service_agreed: Some(true),
            ..Default::default()
        };

        let mut transport = Transport::new(Arc::clone(&self.nonce_pool), acme_key);
        let res = transport
            .call_jwk(&self.api_directory.new_account, &acc)
            .await?;

        let kid = req_expect_header(&res, "location")?;
        log::debug!("Key ID is: {kid}");
        let api_account = res.json::<api::Account>().await?;

        // fill in the server returned key ID
        transport.set_key_id(kid);

        Ok(Account::new(
            transport,
            api_account,
            self.api_directory.clone(),
        ))
    }

    /// Returns a reference to the directory's API object.
    ///
    /// Useful for debugging.
    pub fn api_directory(&self) -> &api::Directory {
        &self.api_directory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_directory() {
        let server = acme_test_server::with_directory_server();

        let url = DirectoryUrl::Other(&server.dir_url);
        let _dir = Directory::fetch(url).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_account() {
        let server = acme_test_server::with_directory_server();

        let url = DirectoryUrl::Other(&server.dir_url);
        let dir = Directory::fetch(url).await.unwrap();

        let _acc = dir
            .register_account(Some(vec!["mailto:foo@bar.com".to_owned()]))
            .await
            .unwrap();
    }
}
