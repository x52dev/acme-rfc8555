use std::{
    collections::VecDeque,
    convert::TryInto,
    sync::{Arc, Mutex},
};

use base64::prelude::*;
use serde::Serialize;
use sha2::Digest as _;

use crate::{
    acc::AcmeKey,
    error::Result,
    jwt::{Jwk, Jws, JwsProtected},
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
    pub fn new(nonce_pool: &Arc<NoncePool>, acme_key: AcmeKey) -> Self {
        Transport {
            acme_key,
            nonce_pool: nonce_pool.clone(),
        }
    }

    /// Update the key id once it is known (part of setting up the transport).
    pub fn set_key_id(&mut self, kid: String) {
        self.acme_key.set_key_id(kid);
    }

    /// The key used in the transport
    pub fn acme_key(&self) -> &AcmeKey {
        &self.acme_key
    }

    /// Make call using the full jwk. Only for the first newAccount request.
    pub async fn call_jwk<T: Serialize + ?Sized>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        self.do_call(url, body, jws_with_jwk).await
    }

    /// Make call using the key id
    pub async fn call<T: Serialize + ?Sized>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        self.do_call(url, body, jws_with_kid).await
    }

    async fn do_call<T: Serialize + ?Sized, F: Fn(&str, String, &AcmeKey, &T) -> Result<String>>(
        &self,
        url: &str,
        body: &T,
        make_body: F,
    ) -> Result<reqwest::Response> {
        // The ACME API may at any point invalidate all nonces. If we detect such an
        // error, we loop until the server accepts the nonce.
        loop {
            // Either get a new nonce, or reuse one from a previous request.
            let nonce = self.nonce_pool.get_nonce().await?;

            // Sign the body.
            let body = make_body(url, nonce, &self.acme_key, body)?;

            log::debug!("Call endpoint {}", url);

            // Post it to the URL
            let response = req_post(url, &body).await;

            // Regardless of the request being a success or not, there might be
            // a nonce in the response.
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
                    log::debug!("Retrying on: {}", problem);
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
            nonce_url: nonce_url.into(),
            ..Default::default()
        }
    }

    fn extract_nonce(&self, res: &reqwest::Response) {
        if let Some(nonce) = res.headers().get("replay-nonce") {
            log::trace!("Extract nonce");
            let mut pool = self.pool.lock().unwrap();
            pool.push_back(nonce.to_str().unwrap().to_owned());
            if pool.len() > 10 {
                pool.pop_front();
            }
        }
    }

    async fn get_nonce(&self) -> Result<String> {
        {
            let mut pool = self.pool.lock().unwrap();
            if let Some(nonce) = pool.pop_front() {
                log::trace!("Use previous nonce");
                return Ok(nonce);
            }
        }
        log::debug!("Request new nonce");
        let res = req_head(&self.nonce_url).await;
        Ok(req_expect_header(&res, "replay-nonce")?)
    }
}

fn jws_with_kid<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let protected = JwsProtected::new_kid(key.key_id(), url, nonce);
    jws_with(protected, key, payload)
}

fn jws_with_jwk<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let jwk: Jwk = key.try_into()?;
    let protected = JwsProtected::new_jwk(jwk, url, nonce);
    jws_with(protected, key, payload)
}

fn jws_with<T: Serialize + ?Sized>(
    protected: JwsProtected,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let protected = {
        let pro_json = serde_json::to_string(&protected)?;
        BASE64_URL_SAFE_NO_PAD.encode(pro_json.as_bytes())
    };
    let payload = {
        let pay_json = serde_json::to_string(payload)?;
        if pay_json == "\"\"" {
            // This is a special case produced by ApiEmptyString and should
            // not be further base64url encoded.
            "".to_string()
        } else {
            BASE64_URL_SAFE_NO_PAD.encode(pay_json.as_bytes())
        }
    };

    let to_sign = format!("{}.{}", protected, payload);
    let digest = sha2::Sha256::digest(to_sign.as_bytes());
    let (sig, _rec_id) = key.signing_key().sign_recoverable(&digest).unwrap();
    let r = sig.r().to_bytes().to_vec();
    let s = sig.s().to_bytes().to_vec();

    let mut v = Vec::with_capacity(r.len() + s.len());
    v.extend_from_slice(&r);
    v.extend_from_slice(&s);
    let signature = BASE64_URL_SAFE_NO_PAD.encode(&v);

    let jws = Jws::new(protected, payload, signature);

    Ok(serde_json::to_string(&jws)?)
}
