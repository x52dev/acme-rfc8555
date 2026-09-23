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
}
