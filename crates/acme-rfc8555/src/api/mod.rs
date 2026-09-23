//! JSON API payloads.
//!
//! Not intended to be used directly. Provided to aid debugging.

use std::fmt;

use serde::{
    ser::{SerializeMap as _, Serializer},
    Deserialize, Serialize,
};

mod account;
mod authorization;
mod challenge;
mod directory;
mod finalize;
mod identifier;
mod order;
mod revocation;

pub use self::{
    account::Account,
    authorization::{Authorization, AuthorizationStatus},
    challenge::{Challenge, ChallengeStatus},
    directory::{Directory, DirectoryMeta},
    finalize::Finalize,
    identifier::Identifier,
    order::{Order, OrderStatus},
    revocation::Revocation,
};

/// Serializes to `""`.
pub struct EmptyString;

impl Serialize for EmptyString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("")
    }
}

/// Serializes to `{}`.
pub struct EmptyObject;

impl Serialize for EmptyObject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_map(Some(0))?.end()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub _type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subproblems: Option<Vec<Subproblem>>,
}

impl Problem {
    /// Returns true if problem type is "badNonce".
    pub fn is_bad_nonce(&self) -> bool {
        self._type == "badNonce"
    }

    /// Returns true if problem details indicate that JWS verification failed.
    pub fn is_jws_verification_error(&self) -> bool {
        (self._type == "urn:ietf:params:acme:error:malformed"
            || self._type == "urn:acme:error:malformed")
            && self
                .detail
                .as_deref()
                .is_some_and(|detail| detail == "JWS verification error")
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{}: {detail}", self._type),
            _ => write!(f, "{}", self._type),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subproblem {
    #[serde(rename = "type")]
    pub _type: String,
    pub detail: Option<String>,
    pub identifier: Option<identifier::Identifier>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_empty_string() {
        let x = serde_json::to_string(&EmptyString).unwrap();
        assert_eq!("\"\"", x);
    }

    #[test]
    fn test_api_empty_object() {
        let x = serde_json::to_string(&EmptyObject).unwrap();
        assert_eq!("{}", x);
    }

    #[test]
    fn bad_nonce_matches_only_the_bad_nonce_type() {
        let problem = Problem {
            _type: "badNonce".to_owned(),
            ..Default::default()
        };

        assert!(problem.is_bad_nonce());
        assert!(!Problem::default().is_bad_nonce());
    }

    #[test]
    fn jws_verification_error_accepts_both_malformed_types() {
        for problem_type in [
            "urn:ietf:params:acme:error:malformed",
            "urn:acme:error:malformed",
        ] {
            let problem = Problem {
                _type: problem_type.to_owned(),
                detail: Some("JWS verification error".to_owned()),
                ..Default::default()
            };

            assert!(problem.is_jws_verification_error(), "{problem_type}");
        }
    }

    #[test]
    fn jws_verification_error_requires_exact_detail() {
        let problem = Problem {
            _type: "urn:ietf:params:acme:error:malformed".to_owned(),
            detail: Some("other malformed request".to_owned()),
            ..Default::default()
        };

        assert!(!problem.is_jws_verification_error());
    }

    #[test]
    fn jws_verification_error_requires_malformed_type() {
        let problem = Problem {
            _type: "urn:ietf:params:acme:error:unauthorized".to_owned(),
            detail: Some("JWS verification error".to_owned()),
            ..Default::default()
        };

        assert!(!problem.is_jws_verification_error());
    }
}
