use std::convert::TryFrom;

use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::acc::AcmeKey;

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct JwsProtected {
    alg: String,
    url: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl JwsProtected {
    pub(crate) fn new_jwk(jwk: Jwk, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".to_owned(),
            url: url.to_owned(),
            nonce,
            jwk: Some(jwk),
            ..Default::default()
        }
    }

    pub(crate) fn new_kid(kid: &str, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".to_owned(),
            url: url.to_owned(),
            nonce,
            kid: Some(kid.to_owned()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Jwk {
    alg: String,
    crv: String,
    kty: String,
    #[serde(rename = "use")]
    _use: String,
    x: String,
    y: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// LEXICAL ORDER OF FIELDS MATTER!
pub(crate) struct JwkThumb {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

impl TryFrom<&AcmeKey> for Jwk {
    type Error = anyhow::Error;

    fn try_from(a: &AcmeKey) -> anyhow::Result<Self> {
        let point = a.signing_key().verifying_key().to_encoded_point(false);

        let x = point.x().unwrap();
        let y = point.y().unwrap();

        Ok(Jwk {
            alg: "ES256".to_owned(),
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            _use: "sig".to_owned(),
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
        })
    }
}

impl From<&Jwk> for JwkThumb {
    fn from(a: &Jwk) -> Self {
        JwkThumb {
            crv: a.crv.clone(),
            kty: a.kty.clone(),
            x: a.x.clone(),
            y: a.y.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

impl Jws {
    pub(crate) fn new(protected: String, payload: String, signature: String) -> Self {
        Jws {
            protected,
            payload,
            signature,
        }
    }
}
