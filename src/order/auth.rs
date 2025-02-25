use std::{sync::Arc, time::Duration};

use base64::prelude::*;
use sha2::{Digest as _, Sha256};

use crate::{
    acc::{AccountInner, AcmeKey},
    api,
    jws::{Jwk, JwkThumb},
};

/// An authorization ([ownership proof]) for a domain name.
///
/// Each authorization for an order much be progressed to a valid state before the ACME API
/// will issue a certificate.
///
/// Authorizations may or may not be required depending on previous orders against the same
/// ACME account. The ACME API decides if the authorization is needed.
///
/// Currently there are two ways of providing the authorization.
///
/// * In a text file served using [HTTP] from a web server of the domain being authorized.
/// * A `TXT` [DNS] record under the domain being authorized.
///
/// [ownership proof]: ../index.html#domain-ownership
/// [HTTP]: #method.http_challenge
/// [DNS]: #method.dns_challenge
#[derive(Debug)]
pub struct Auth {
    inner: Arc<AccountInner>,
    api_auth: api::Authorization,
    auth_url: String,
}

impl Auth {
    pub(crate) fn new(
        inner: &Arc<AccountInner>,
        api_auth: api::Authorization,
        auth_url: &str,
    ) -> Self {
        Auth {
            inner: inner.clone(),
            api_auth,
            auth_url: auth_url.to_owned(),
        }
    }

    /// Domain name for this authorization.
    pub fn domain_name(&self) -> &str {
        &self.api_auth.identifier.value
    }

    /// Whether we actually need to do the authorization. This might not be needed if we have
    /// proven ownership of the domain recently in a previous order.
    pub fn need_challenge(&self) -> bool {
        !matches!(self.api_auth.status, api::AuthorizationStatus::Valid)
    }

    /// Get the http challenge.
    ///
    /// The http challenge must be placed so it is accessible under:
    ///
    /// ```text
    /// http://<domain-to-be-proven>/.well-known/acme-challenge/<token>
    /// ```
    ///
    /// The challenge will be accessed over HTTP (not HTTPS), for obvious reasons.
    ///
    /// ```no_run
    /// use std::{fs::File, io::Write as _, time::Duration};
    ///
    /// use acme::order::Auth;
    ///
    /// async fn web_authorize(auth: &Auth) -> eyre::Result<()> {
    ///   let challenge = auth.http_challenge().unwrap();
    ///
    ///   // Assuming our web server's root is under /var/www
    ///   let path = {
    ///     let token = challenge.http_token();
    ///     format!("/var/www/.well-known/acme-challenge/{}", token)
    ///   };
    ///
    ///   let mut file = File::create(&path)?;
    ///   file.write_all(challenge.http_proof()?.as_bytes())?;
    ///   challenge.validate(Duration::from_millis(5000)).await?;
    ///
    ///   Ok(())
    /// }
    /// ```
    pub fn http_challenge(&self) -> Option<Challenge<Http>> {
        self.api_auth
            .http_challenge()
            .map(|c| Challenge::new(&self.inner, c.clone(), &self.auth_url))
    }

    /// Get the dns challenge.
    ///
    /// The dns challenge is a `TXT` record that must put created under:
    ///
    /// ```text
    /// _acme-challenge.<domain-to-be-proven>.  TXT  <proof>
    /// ```
    ///
    /// The `<proof>` contains the signed token proving this account update it.
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use acme::order::Auth;
    ///
    /// async fn dns_authorize(auth: &Auth) -> eyre::Result<()> {
    ///   let challenge = auth.dns_challenge().unwrap();
    ///   let record = format!("_acme-challenge.{}.", auth.domain_name());
    ///   // route_53_set_record(&record, "TXT", challenge.dns_proof());
    ///   challenge.validate(Duration::from_millis(5000)).await?;
    ///   Ok(())
    /// }
    /// ```
    ///
    /// The dns proof is not the same as the http proof.
    pub fn dns_challenge(&self) -> Option<Challenge<Dns>> {
        self.api_auth
            .dns_challenge()
            .map(|c| Challenge::new(&self.inner, c.clone(), &self.auth_url))
    }

    /// Returns the TLS ALPN challenge.
    ///
    /// The TLS ALPN challenge is a certificate that must be served when a TLS connection is made
    /// with the ALPN protocol "acme-tls/1". The certificate must contain a single dNSName SAN
    /// containing the domain being validated, as well as an ACME extension containing the SHA256 of
    /// the key authorization.
    pub fn tls_alpn_challenge(&self) -> Option<Challenge<TlsAlpn>> {
        self.api_auth
            .tls_alpn_challenge()
            .map(|c| Challenge::new(&self.inner, c.clone(), &self.auth_url))
    }

    /// Returns a reference to the authorization's API object.
    ///
    /// Useful for debugging.
    ///
    /// We don't refresh the authorization when the corresponding challenge is validated, so there
    /// will be no changes to see here.
    pub fn api_auth(&self) -> &api::Authorization {
        &self.api_auth
    }
}

/// Marker type for HTTP challenges.
#[doc(hidden)]
pub struct Http;

/// Marker type for DNS challenges.
#[doc(hidden)]
pub struct Dns;

/// Marker type for TLS ALPN challenges.
#[doc(hidden)]
pub struct TlsAlpn;

/// A DNS, HTTP, or TLS-ALPN challenge as obtained from the [`Auth`].
pub struct Challenge<A> {
    inner: Arc<AccountInner>,
    api_challenge: api::Challenge,
    auth_url: String,
    _ph: std::marker::PhantomData<A>,
}

/// See [RFC 8555 §8.3].
///
/// [RFC 8555 §8.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-8.3
impl Challenge<Http> {
    /// Returns the token, a unique identifier of the challenge.
    ///
    /// This is used as the file name in the HTTP challenge like so:
    ///
    /// ```text
    /// http://<domain-to-be-proven>/.well-known/acme-challenge/<token>
    /// ```
    pub fn http_token(&self) -> &str {
        &self.api_challenge.token
    }

    /// Returns the proof content for HTTP validation.
    ///
    /// Proof is typically placed in a text file that is served as the file named by `token`.
    pub fn http_proof(&self) -> eyre::Result<String> {
        let acme_key = self.inner.transport.acme_key();
        let proof = key_authorization(&self.api_challenge.token, acme_key, false)?;
        Ok(proof)
    }
}

/// See [RFC 8555 §8.4].
///
/// [RFC 8555 §8.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-8.4
impl Challenge<Dns> {
    /// Returns the proof content for DNS validation.
    ///
    /// Proof is to be placed in a DNS TXT record like so:
    ///
    /// ```plain
    /// _acme-challenge.<domain-to-be-proven>.  TXT  <proof>
    /// ```
    pub fn dns_proof(&self) -> eyre::Result<String> {
        let acme_key = self.inner.transport.acme_key();
        let proof = key_authorization(&self.api_challenge.token, acme_key, true)?;
        Ok(proof)
    }
}

/// See [RFC 8737 §3].
///
/// [RFC 8737 §3]: https://datatracker.ietf.org/doc/html/rfc8737#section-3
impl Challenge<TlsAlpn> {
    /// Returns the proof content for TLS-ALPN validation.
    ///
    /// Proof is to be placed in the certificate used for validation.
    pub fn tls_alpn_proof(&self) -> eyre::Result<[u8; 32]> {
        let acme_key = self.inner.transport.acme_key();
        let proof = key_authorization(&self.api_challenge.token, acme_key, false)?;

        Ok(Sha256::digest(proof).into())
    }
}

impl<A> Challenge<A> {
    fn new(inner: &Arc<AccountInner>, api_challenge: api::Challenge, auth_url: &str) -> Self {
        Challenge {
            inner: inner.clone(),
            api_challenge,
            auth_url: auth_url.to_owned(),
            _ph: std::marker::PhantomData,
        }
    }

    /// Returns true if this challenge needs validation.
    ///
    /// It might already been done in a previous order for the same account.
    pub fn need_validate(&self) -> bool {
        matches!(self.api_challenge.status, api::ChallengeStatus::Pending)
    }

    /// Tells the ACME API to attempt to validate the proof of this challenge.
    ///
    /// The challenge proof must be put in place before this call. Either by: placing it in a DNS
    /// record, updating a web server, or passing it to TLS connection for ALPN exchange.
    pub async fn validate(&self, delay: Duration) -> eyre::Result<()> {
        let res = self
            .inner
            .transport
            .call_kid(&self.api_challenge.url, &api::EmptyObject)
            .await?;

        let _api_challenge = res.json::<api::Challenge>().await?;

        let auth = poll_authorization_result(&self.inner, &self.auth_url, delay).await?;

        if !matches!(auth.status, api::AuthorizationStatus::Valid) {
            let error = auth
                .challenges
                .iter()
                .filter_map(|c| c.error.as_ref())
                .next();

            let reason = match error {
                Some(error) => format!("{error} (subproblems: {:?})", error.subproblems),
                None => "Validation failed and no error found".to_owned(),
            };

            return Err(eyre::eyre!("Validation failed: {reason}"));
        }

        Ok(())
    }

    /// Returns a reference to the challenge's API object.
    ///
    /// Useful for debugging.
    pub fn api_challenge(&self) -> &api::Challenge {
        &self.api_challenge
    }
}

fn key_authorization(token: &str, key: &AcmeKey, extra_sha256: bool) -> eyre::Result<String> {
    let jwk = Jwk::try_from(key)?;
    let jwk_thumb = JwkThumb::from(&jwk);
    let jwk_json = serde_json::to_string(&jwk_thumb)?;

    let digest = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(jwk_json));
    let key_auth = format!("{token}.{digest}");

    let res = if extra_sha256 {
        BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(key_auth))
    } else {
        key_auth
    };

    Ok(res)
}

/// Polls the authorization status until it transitions out of the "pending" state.
async fn poll_authorization_result(
    acc: &AccountInner,
    auth_url: &str,
    delay: Duration,
) -> eyre::Result<api::Authorization> {
    let auth = loop {
        let auth = acc
            .transport
            .call_kid(auth_url, &api::EmptyString)
            .await?
            .json::<api::Authorization>()
            .await?;

        if !matches!(auth.status, api::AuthorizationStatus::Pending) {
            break auth;
        }

        tokio::time::sleep(delay).await;
    };

    Ok(auth)
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test]
    async fn test_get_challenges() {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let dir = Directory::fetch(url).await.unwrap();
        let acc = dir
            .register_account(Some(vec!["mailto:foo@bar.com".to_owned()]))
            .await
            .unwrap();
        let ord = acc.new_order("acme-test.example.com", &[]).await.unwrap();
        let authz = ord.authorizations().await.unwrap();
        assert!(authz.len() == 1);
        let auth = &authz[0];

        let http = auth.http_challenge().unwrap();
        assert!(http.need_validate());

        let dns = auth.dns_challenge().unwrap();
        assert!(dns.need_validate());
    }
}
