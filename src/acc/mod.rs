use std::sync::Arc;

use base64::prelude::*;
use zeroize::Zeroizing;

use crate::{
    api::{ApiAccount, ApiDirectory, ApiIdentifier, ApiOrder, ApiRevocation},
    cert::Certificate,
    error::Result,
    order::{NewOrder, Order},
    req::req_expect_header,
    trans::Transport,
};

mod acme_key;

pub(crate) use self::acme_key::AcmeKey;

#[derive(Clone, Debug)]
pub(crate) struct AccountInner {
    pub transport: Transport,
    pub api_account: ApiAccount,
    pub api_directory: ApiDirectory,
}

/// Account with an ACME provider.
///
/// Accounts are created using [`Directory::account`] and consist of a contact
/// email address and a private key for signing requests to the ACME API.
///
/// acme-lib uses elliptic curve P-256 for accessing the account. This
/// does not affect which key algorithms that can be used for the
/// issued certificates.
///
/// The advantage of using elliptic curve cryptography is that the signed
/// requests against the ACME lib are kept small and that the public key
/// can be derived from the private.
///
/// [`Directory::account`]: struct.Directory.html#method.account
#[derive(Clone)]
pub struct Account {
    inner: Arc<AccountInner>,
}

impl Account {
    pub(crate) fn new(
        transport: Transport,
        api_account: ApiAccount,
        api_directory: ApiDirectory,
    ) -> Self {
        Account {
            inner: Arc::new(AccountInner {
                transport,
                api_account,
                api_directory,
            }),
        }
    }

    /// Private key for this account.
    ///
    /// The key is an elliptic curve private key.
    pub fn acme_private_key_pem(&self) -> Result<Zeroizing<String>> {
        self.inner.transport.acme_key().to_pem()
    }

    /// Create a new order to issue a certificate for this account.
    ///
    /// Each order has a required `primary_name` (which will be set as the certificates `CN`)
    /// and a variable number of `alt_names`.
    ///
    /// This library doesn't constrain the number of `alt_names`, but it is limited by the ACME
    /// API provider. Let's Encrypt sets a max of [100 names] per certificate.
    ///
    /// Every call creates a new order with the ACME API provider, even when the domain
    /// names supplied are exactly the same.
    ///
    /// [100 names]: https://letsencrypt.org/docs/rate-limits/
    pub async fn new_order(&self, primary_name: &str, alt_names: &[&str]) -> Result<NewOrder> {
        // construct the identifiers
        let prim_arr = [primary_name];
        let domains = prim_arr.iter().chain(alt_names);
        let order = ApiOrder {
            identifiers: domains
                .map(|s| ApiIdentifier {
                    _type: "dns".into(),
                    value: s.to_string(),
                })
                .collect(),
            ..Default::default()
        };

        let new_order_url = &self.inner.api_directory.new_order;

        let res = self.inner.transport.call(new_order_url, &order).await?;
        let order_url = req_expect_header(&res, "location")?;
        let api_order = res.json::<ApiOrder>().await?;

        let order = Order::new(&self.inner, api_order, order_url);
        Ok(NewOrder { order })
    }

    /// Revoke a certificate for the reason given.
    pub async fn revoke_certificate(
        &self,
        cert: &Certificate,
        reason: RevocationReason,
    ) -> Result<()> {
        // convert to base64url of the DER (which is not PEM).
        let certificate = BASE64_URL_SAFE_NO_PAD.encode(cert.certificate_der()?);

        let revoc = ApiRevocation {
            certificate,
            reason: reason as usize,
        };

        let url = &self.inner.api_directory.revoke_cert;
        self.inner.transport.call(url, &revoc).await?;

        Ok(())
    }

    /// Access the underlying JSON object for debugging.
    pub fn api_account(&self) -> &ApiAccount {
        &self.inner.api_account
    }
}

/// Enumeration of reasons for revocation.
///
/// The reason codes are taken from [rfc5280](https://tools.ietf.org/html/rfc5280#section-5.3.1).
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // value 7 is not used
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Directory, DirectoryUrl};

    #[tokio::test]
    async fn test_create_order() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let dir = Directory::from_url(url).await?;
        let acc = dir
            .register_account(Some(vec!["mailto:foo@bar.com".to_string()]))
            .await?;
        let _ = acc.new_order("acmetest.example.com", &[]).await?;
        Ok(())
    }
}
