use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::{acc::AcmeKey, util::base64url, Result};

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
            alg: "ES256".into(),
            url: url.into(),
            nonce,
            jwk: Some(jwk),
            ..Default::default()
        }
    }
    pub(crate) fn new_kid(kid: &str, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".into(),
            url: url.into(),
            nonce,
            kid: Some(kid.into()),
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
    type Error = crate::Error;
    fn try_from(a: &AcmeKey) -> Result<Self> {
        let point = a.signing_key().verifying_key().to_encoded_point(false);

        let x = point.x().unwrap();
        let y = point.y().unwrap();

        Ok(Jwk {
            alg: "ES256".into(),
            kty: "EC".into(),
            crv: "P-256".into(),
            _use: "sig".into(),
            x: base64url(&x),
            y: base64url(&y),
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
