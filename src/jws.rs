//! See [RFC 8555 §6.2](https://datatracker.ietf.org/doc/html/rfc8555#section-6.2).

use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::acc::AcmeKey;

/// JWT Protected Header scheme as defined in [RFC 8555 §6.2].
///
/// > For newAccount requests, and for revokeCert requests authenticated by a certificate key,
/// there MUST be a "jwk" field. This field MUST contain the public key corresponding to the
/// private key used to sign the JWS.
/// >
/// > For all other requests, the request is signed using an existing account, and there MUST be a
/// "kid" field. This field MUST contain the account URL received by POSTing to the newAccount
/// resource.
///
/// [RFC 8555 §6.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-6.2
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct JwsProtectedHeader {
    /// Algorithm.
    ///
    /// This field MUST NOT contain "none" or a Message Authentication Code (MAC) algorithm (e.g.
    /// one in which the algorithm registry description mentions MAC/HMAC).
    ///
    /// > An ACME server MUST implement the "ES256" signature algorithm (RFC 7518) and SHOULD
    /// implement the "EdDSA" signature algorithm using the "Ed25519" variant (indicated by "crv")
    /// (RFC 8037).
    alg: String,

    /// A unique value that enables the verifier of a JWS to recognize when replay has occurred.
    ///
    /// As defined in [RFC 8555 §6.5].
    ///
    /// > The value of the "nonce" header parameter MUST be an octet string, encoded according to
    /// the base64url encoding. If the value of a "nonce" header parameter is not valid according to
    /// this encoding, then the verifier MUST reject the JWS as malformed
    ///
    /// [RFC 8555 §6.5: https://datatracker.ietf.org/doc/html/rfc8555#section-6.5.
    nonce: String,

    /// Defined in [RFC 8555 §6.4].
    ///
    /// > The "url" header parameter specifies the URL (RFC 3986) to which this JWS object is
    /// directed. The "url" header parameter MUST be carried in the protected header of the JWS. The
    /// value of the "url" header parameter MUST be a string representing the target URL.
    ///
    /// [RFC 8555 §6.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-6.4
    url: String,

    /// JSON Web Key.
    ///
    /// Mutually exclusive with `kid` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,

    /// Key ID.
    ///
    /// Mutually exclusive with `jwk` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl JwsProtectedHeader {
    /// TODO: implement EdDSA (via Ed25519)

    pub(crate) fn new_jwk(jwk: Jwk, url: &str, nonce: String) -> Self {
        JwsProtectedHeader {
            alg: "ES256".to_owned(),
            url: url.to_owned(),
            nonce,
            jwk: Some(jwk),
            ..Default::default()
        }
    }

    pub(crate) fn new_kid(kid: &str, url: &str, nonce: String) -> Self {
        JwsProtectedHeader {
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

impl TryFrom<&AcmeKey> for Jwk {
    type Error = eyre::Error;

    fn try_from(a: &AcmeKey) -> eyre::Result<Self> {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
// LEXICAL ORDER OF FIELDS MATTER!
pub(crate) struct JwkThumb {
    crv: String,
    kty: String,
    x: String,
    y: String,
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

/// <https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2>
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct FlattenedJsonJws {
    protected: String,
    payload: String,
    signature: String,
}

impl FlattenedJsonJws {
    pub(crate) fn new(protected: String, payload: String, signature: String) -> Self {
        FlattenedJsonJws {
            protected,
            payload,
            signature,
        }
    }
}
