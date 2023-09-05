use std::{collections::VecDeque, sync::Arc};

use base64::prelude::*;
use parking_lot::Mutex;
use serde::Serialize;

use crate::{
    acc::AcmeKey,
    jws::{FlattenedJsonJws, Jwk, JwsProtectedHeader},
    req::{req_expect_header, req_handle_error, req_head, req_post},
};

/// JWS payload and nonce handling for requests to the API.
///
/// Setup is:
///
/// 1. `Transport::new()`
/// 2. `call_jwk()` against newAccount url
/// 3. `set_key_id` from the returned `Location` header.
/// 4. `call()` for all calls after that.
#[derive(Clone, Debug)]
pub(crate) struct Transport {
    acme_key: AcmeKey,
    nonce_pool: Arc<NoncePool>,
}

impl Transport {
    pub fn new(nonce_pool: Arc<NoncePool>, acme_key: AcmeKey) -> Self {
        Transport {
            acme_key,
            nonce_pool,
        }
    }

    /// Update the key ID once it is known (part of setting up the transport).
    pub fn set_key_id(&mut self, kid: String) {
        self.acme_key.set_key_id(kid);
    }

    /// The key used in the transport
    pub fn acme_key(&self) -> &AcmeKey {
        &self.acme_key
    }

    /// Make call using the full JWS.
    ///
    /// Only needed for the first newAccount request.
    pub async fn call_jwk<T>(&self, url: &str, body: &T) -> eyre::Result<reqwest::Response>
    where
        T: Serialize + ?Sized,
    {
        fn jws_with_jwk<T: Serialize + ?Sized>(
            url: &str,
            nonce: String,
            key: &AcmeKey,
            payload: &T,
        ) -> eyre::Result<String> {
            let jwk = Jwk::try_from(key)?;
            let protected = JwsProtectedHeader::new_jwk(jwk, url, nonce);
            jws_with(protected, key, payload)
        }

        self.do_call(url, body, jws_with_jwk).await
    }

    /// Make call using the key ID.
    pub async fn call_kid<T>(&self, url: &str, body: &T) -> eyre::Result<reqwest::Response>
    where
        T: Serialize + ?Sized,
    {
        fn jws_with_kid<T: Serialize + ?Sized>(
            url: &str,
            nonce: String,
            key: &AcmeKey,
            payload: &T,
        ) -> eyre::Result<String> {
            let protected = JwsProtectedHeader::new_kid(key.key_id(), url, nonce);
            jws_with(protected, key, payload)
        }

        self.do_call(url, body, jws_with_kid).await
    }

    async fn do_call<T, F>(
        &self,
        url: &str,
        body: &T,
        make_body: F,
    ) -> eyre::Result<reqwest::Response>
    where
        T: Serialize + ?Sized,
        F: Fn(&str, String, &AcmeKey, &T) -> eyre::Result<String>,
    {
        // The ACME API may at any point invalidate all nonces. If we detect such an
        // error, we loop until the server accepts the nonce.
        loop {
            // Either get a new nonce, or reuse one from a previous request.
            let nonce = self.nonce_pool.get_nonce().await?;

            // Sign the body.
            let body = make_body(url, nonce, &self.acme_key, body)?;

            log::debug!("Call endpoint: {url}");

            // Post it to the URL
            let response = req_post(url, &body).await;

            // Regardless of the request being a success or not, there might be a nonce in the
            // response.
            self.nonce_pool.extract_nonce(&response);

            // Turn errors into ApiProblem.
            let result = req_handle_error(response).await;

            if let Err(problem) = &result {
                if problem.is_bad_nonce() {
                    // retry the request with a new nonce.
                    log::debug!("Retrying on bad nonce");
                    continue;
                }

                // it seems we sometimes make bad JWTs. Why?!
                if problem.is_jwt_verification_error() {
                    log::debug!("Retrying on: {problem}");
                    continue;
                }
            }

            return Ok(result?);
        }
    }
}

/// Shared pool of nonces.
#[derive(Default, Debug)]
pub(crate) struct NoncePool {
    nonce_url: String,
    pool: Mutex<VecDeque<String>>,
}

impl NoncePool {
    pub fn new(nonce_url: &str) -> Self {
        NoncePool {
            nonce_url: nonce_url.to_owned(),
            ..Default::default()
        }
    }

    fn extract_nonce(&self, res: &reqwest::Response) {
        if let Some(nonce) = res.headers().get("replay-nonce") {
            log::trace!("Extracting new nonce");

            let mut pool = self.pool.lock();

            // TODO: ignore invalid replay-nonce values
            // see https://datatracker.ietf.org/doc/html/rfc8555#section-6.5.1
            pool.push_back(nonce.to_str().unwrap().to_owned());

            if pool.len() > 10 {
                pool.pop_front();
            }
        }
    }

    async fn get_nonce(&self) -> eyre::Result<String> {
        {
            let mut pool = self.pool.lock();

            if let Some(nonce) = pool.pop_front() {
                log::trace!("Use previous nonce");
                return Ok(nonce);
            }
        }

        log::debug!("Request new nonce");
        let res = req_head(&self.nonce_url).await;

        // TODO: ignore invalid replay-nonce values
        // see https://datatracker.ietf.org/doc/html/rfc8555#section-6.5.1
        Ok(req_expect_header(&res, "replay-nonce")?)
    }
}

/// Construct JWS with protected header according to [RFC 7515 §5.1].
///
/// [RFC 7515 §5.1]: https://datatracker.ietf.org/doc/html/rfc7515#section-5.1
fn jws_with<T: Serialize + ?Sized>(
    protected: JwsProtectedHeader,
    key: &AcmeKey,
    payload: &T,
) -> eyre::Result<String> {
    let header = {
        let pro_json = serde_json::to_string(&protected)?;
        BASE64_URL_SAFE_NO_PAD.encode(pro_json)
    };

    let payload = {
        let payload_json = serde_json::to_string(payload)?;

        // HACK: empty string detection is bad way to do this
        if payload_json == "\"\"" {
            // This is a special case produced by ApiEmptyString and should
            // not be further base64url encoded.
            String::new()
        } else {
            BASE64_URL_SAFE_NO_PAD.encode(payload_json)
        }
    };

    let to_sign = format!("{header}.{payload}");
    let (signature, _rec_id) = key
        .signing_key()
        .sign_recoverable(to_sign.as_bytes())
        .unwrap();

    let signature = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let jws = FlattenedJsonJws::new(header, payload, signature);

    Ok(serde_json::to_string(&jws)?)
}
