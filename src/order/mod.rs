//! Order life cycle.
//!
//! An order goes through a life cycle of different states that require various actions by
//! the user. To ensure the user only use appropriate actions, this library have simple façade
//! structs that wraps the actual [`api::Order`].
//!
//! 1. First prove ownership:
//!    * [`NewOrder`] -> [`Auth`]* -> [`Challenge`]
//! 2. Then submit CSR and download the cert.
//!    * [`NewOrder`] -> [`CsrOrder`] -> [`CertOrder`]
//!
//! \* Possibly multiple auths.

use std::{sync::Arc, time::Duration};

use base64::prelude::*;
use der::Encode as _;
use pkcs8::EncodePrivateKey as _;

use crate::{
    acc::AccountInner,
    api,
    cert::{create_csr, Certificate},
};

mod auth;

pub use self::auth::{Auth, Challenge};

/// The order wrapped with an outer facade.
pub(crate) struct Order {
    acc: Arc<AccountInner>,
    pub(crate) api_order: api::Order,
    url: String,
}

impl Order {
    pub(crate) fn new(acc: &Arc<AccountInner>, api_order: api::Order, url: String) -> Self {
        Order {
            acc: Arc::clone(acc),
            api_order,
            url,
        }
    }
}

/// Helper to refresh an order status (POST-as-GET).
pub(crate) async fn refresh_order(
    acc: &Arc<AccountInner>,
    url: String,
    want_status: &'static str,
) -> eyre::Result<Order> {
    let res = acc.transport.call_kid(&url, &api::EmptyString).await?;

    // our test rig requires the order to be in `want_status`.
    // api_order_of is different for test compilation
    let api_order = api_order_of(res, want_status).await?;

    Ok(Order {
        acc: Arc::clone(acc),
        api_order,
        url,
    })
}

#[cfg(not(test))]
async fn api_order_of(res: reqwest::Response, _want_status: &str) -> eyre::Result<api::Order> {
    Ok(res.json().await?)
}

#[cfg(test)]
// our test rig requires the order to be in `want_status`
async fn api_order_of(res: reqwest::Response, want_status: &str) -> eyre::Result<api::Order> {
    let body = res.text().await?;

    #[allow(clippy::trivial_regex)]
    let re = regex::Regex::new("<STATUS>").unwrap();
    let body = re.replace_all(&body, want_status).into_owned();

    Ok(serde_json::from_str::<api::Order>(&body)?)
}

/// A new order created by [`Account::new_order()`].
///
/// An order is created using one or many domains (a primary `CN` and possible multiple
/// alt names). All domains in the order must have authorizations ([confirmed ownership])
/// before the order can progress to submitting a [CSR].
///
/// This order façade provides calls to provide such authorizations and to progress the order
/// when ready.
///
/// The ACME API provider might "remember" for a time that you already own a domain, which
/// means you might not need to prove the ownership every time. Use appropriate methods to
/// first check whether you really need to handle authorizations.
///
/// [`Account::new_order()`]: crate::Account::new_order()
/// [confirmed ownership]: ../index.html#domain-ownership
/// [CSR]: https://en.wikipedia.org/wiki/Certificate_signing_request
pub struct NewOrder {
    pub(crate) order: Order,
}

impl NewOrder {
    /// Tell if the domains in this order have been authorized.
    ///
    /// This doesn't do any calls against the API. You must manually call [`refresh`].
    ///
    /// In ACME API terms, the order can either be `ready` or `valid`, which both would mean we have
    /// passed the authorization stage.
    ///
    /// [`refresh`]: Self::refresh
    pub fn is_validated(&self) -> bool {
        self.order.api_order.status.is_some_and(|status| {
            matches!(status, api::OrderStatus::Ready | api::OrderStatus::Valid)
        })
    }

    /// If the order [is validated], progress it to a [`CsrOrder`].
    ///
    /// This doesn't do any calls against the API. You must manually call [`refresh`].
    ///
    /// [is validated]: Self::is_validated
    /// [`refresh`]: Self::refresh
    pub fn confirm_validations(&self) -> Option<CsrOrder> {
        if self.is_validated() {
            Some(CsrOrder {
                order: Order::new(
                    &self.order.acc,
                    self.order.api_order.clone(),
                    self.order.url.clone(),
                ),
            })
        } else {
            None
        }
    }

    /// Refresh the order state against the ACME API.
    ///
    /// The specification calls this a "POST-as-GET" against the order URL.
    pub async fn refresh(&mut self) -> eyre::Result<()> {
        let order = refresh_order(&self.order.acc, self.order.url.clone(), "ready").await?;
        self.order.api_order.overwrite(order.api_order)?;
        Ok(())
    }

    /// Provide the authorizations. The number of authorizations will be the same as
    /// the number of domains requests, i.e. at least one (the primary CN), but possibly
    /// more (for alt names).
    ///
    /// If the order includes new domain names that have not been authorized before, this
    /// list might contain a mix of already valid and not yet valid auths.
    pub async fn authorizations(&self) -> eyre::Result<Vec<Auth>> {
        let mut result = vec![];
        if let Some(authorizations) = &self.order.api_order.authorizations {
            for auth_url in authorizations {
                let res = self
                    .order
                    .acc
                    .transport
                    .call_kid(auth_url, &api::EmptyString)
                    .await?;
                let api_auth = res.json::<api::Authorization>().await?;
                result.push(Auth::new(&self.order.acc, api_auth, auth_url));
            }
        }
        Ok(result)
    }

    /// Returns a reference to the order's API object.
    ///
    /// Useful for debugging.
    pub fn api_order(&self) -> &api::Order {
        &self.order.api_order
    }
}

/// An order that is ready for a [CSR] submission.
///
/// Submitting the CSR is called "finalizing" the order.
///
/// To finalize, the user supplies a private key (from which a public key is derived). This library
/// provides [a function to create a P-256 private key](crate::create_p256_key()) (since this is the
/// only private key type currently supported) but it can be created or retrieved in some other way.
///
/// Let's Encrypt [supports] this key type, but if an alternative ACME provider does not support
/// this algorithm, it will show as an error when finalizing the order.
///
/// [CSR]: https://en.wikipedia.org/wiki/Certificate_signing_request
/// [supports]: https://letsencrypt.org/docs/integration-guide/#supported-key-algorithms
pub struct CsrOrder {
    pub(crate) order: Order,
}

impl CsrOrder {
    /// Finalizes the order by submitting a CSR and awaiting certificate issuance.
    ///
    /// Creates the CSR for the domains in the order and submit it to the ACME API.
    ///
    /// Once the CSR has been submitted, the order goes into a "processing" status, where we must
    /// poll until the status changes to "valid"; `interval` is the amount of time to wait between
    /// each poll attempt.
    pub async fn finalize(
        mut self,
        private_key: p256::ecdsa::SigningKey,
        interval: Duration,
    ) -> eyre::Result<CertOrder> {
        // the domains that we have authorized
        let domains = self.order.api_order.domains();

        let csr = create_csr(&private_key, &domains)?;

        let csr_der = csr.to_der()?;
        let csr_b64 = BASE64_URL_SAFE_NO_PAD.encode(&csr_der);
        let finalize = api::Finalize::new(csr_b64);

        let inner = &self.order.acc;
        let order_url = &self.order.url;
        let finalize_url = &self.order.api_order.finalize;

        // If the CSR is invalid, we will get a 4xx code back that bombs out
        // from this retry_call.
        inner.transport.call_kid(finalize_url, &finalize).await?;

        // wait for the status to not be processing:
        // valid -> cert is issued
        // invalid -> the whole thing is off
        let order = poll_order_finalization(&inner, order_url, interval).await?;

        if !matches!(order.api_order.status, Some(api::OrderStatus::Valid)) {
            return Err(eyre::eyre!(
                "Order is in status: {:?}",
                order.api_order.status
            ));
        }

        self.order.api_order.overwrite(order.api_order)?;

        Ok(CertOrder {
            private_key,
            order: self.order,
        })
    }

    /// Returns a reference to the order's API object.
    ///
    /// Useful for debugging.
    pub fn api_order(&self) -> &api::Order {
        &self.order.api_order
    }
}

/// Polls the order status until it transitions out of the "processing" state.
async fn poll_order_finalization(
    acc: &Arc<AccountInner>,
    url: &str,
    interval: Duration,
) -> eyre::Result<Order> {
    loop {
        let order = refresh_order(acc, url.to_owned(), "valid").await?;

        if !matches!(order.api_order.status, Some(api::OrderStatus::Processing)) {
            return Ok(order);
        }

        tokio::time::sleep(interval).await;
    }
}

/// Order for an issued certificate that is ready to download.
pub struct CertOrder {
    private_key: p256::ecdsa::SigningKey,
    order: Order,
}

impl CertOrder {
    /// Request download of the issued certificate.
    pub async fn download_cert(self) -> eyre::Result<Certificate> {
        let url = self
            .order
            .api_order
            .certificate
            .ok_or_else(|| eyre::eyre!("certificate url"))?;

        let inner = self.order.acc;

        let res = inner.transport.call_kid(&url, &api::EmptyString).await?;

        let private_key_pem = self.private_key.to_pkcs8_pem(der::pem::LineEnding::LF)?;

        let certificate = res.text().await?;

        Ok(Certificate::new(private_key_pem, certificate))
    }

    /// Returns a reference to the order's API object.
    ///
    /// Useful for debugging.
    pub fn api_order(&self) -> &api::Order {
        &self.order.api_order
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cert, Directory, DirectoryUrl};

    #[tokio::test]
    async fn test_get_authorizations() {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let dir = Directory::fetch(url).await.unwrap();
        let acc = dir
            .register_account(Some(vec!["mailto:foo@bar.com".to_owned()]))
            .await
            .unwrap();
        let ord = acc.new_order("acme-test.example.com", &[]).await.unwrap();
        let _authorizations = ord.authorizations().await.unwrap();
    }

    #[tokio::test]
    async fn test_finalize() {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let dir = Directory::fetch(url).await.unwrap();
        let acc = dir
            .register_account(Some(vec!["mailto:foo@bar.com".to_owned()]))
            .await
            .unwrap();
        let ord = acc.new_order("acme-test.example.com", &[]).await.unwrap();
        // shortcut auth
        let ord = CsrOrder { order: ord.order };
        let private_key = cert::create_p256_key();
        let _ord = ord
            .finalize(private_key, Duration::from_millis(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_download_and_save_cert() {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let dir = Directory::fetch(url).await.unwrap();
        let acc = dir
            .register_account(Some(vec!["mailto:foo@bar.com".to_owned()]))
            .await
            .unwrap();
        let ord = acc.new_order("acme-test.example.com", &[]).await.unwrap();

        // shortcut auth
        let ord = CsrOrder { order: ord.order };
        let private_key = cert::create_p256_key();
        let ord = ord
            .finalize(private_key, Duration::from_millis(1))
            .await
            .unwrap();

        let cert = ord.download_cert().await.unwrap();
        assert_eq!("CERT HERE", cert.certificate());
        assert!(!cert.private_key().is_empty());
        assert_eq!(cert.valid_days_left().unwrap(), 89);
    }
}
