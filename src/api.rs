//! Low-level API JSON objects.
//!
//! Unstable and not to be used directly. Provided to aid debugging.

use std::fmt;

use serde::{
    ser::{SerializeMap as _, Serializer},
    Deserialize, Serialize,
};

/// Serializes to `""`.
pub struct ApiEmptyString;

impl Serialize for ApiEmptyString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("")
    }
}

/// Serializes to `{}`.
pub struct ApiEmptyObject;

impl Serialize for ApiEmptyObject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_map(Some(0))?.end()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiProblem {
    #[serde(rename = "type")]
    pub _type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subproblems: Option<Vec<ApiSubproblem>>,
}

impl ApiProblem {
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

impl fmt::Display for ApiProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{}: {detail}", self._type),
            _ => write!(f, "{}", self._type),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSubproblem {
    #[serde(rename = "type")]
    pub _type: String,
    pub detail: Option<String>,
    pub identifier: Option<ApiIdentifier>,
}

/// Directory object for ACME client self-configuration.
///
/// See [RFC 8555 §7.1.1].
///
/// # Example JSON
///
/// ```json
/// {
///   "newNonce": "https://example.com/acme/new-nonce",
///   "newAccount": "https://example.com/acme/new-account",
///   "newOrder": "https://example.com/acme/new-order",
///   "newAuthz": "https://example.com/acme/new-authz",
///   "revokeCert": "https://example.com/acme/revoke-cert",
///   "keyChange": "https://example.com/acme/key-change",
///   "meta": {
///     "termsOfService": "https://example.com/acme/terms/2017-5-30",
///     "website": "https://www.example.com/",
///     "caaIdentities": ["example.com"],
///     "externalAccountRequired": false
///   }
/// }
/// ```
///
/// [RFC 8555 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiDirectory {
    /// URL for new nonce requests.
    pub new_nonce: String,

    /// URL for new account requests.
    pub new_account: String,

    /// URL for new order requests.
    pub new_order: String,

    /// URL for new authorization requests.
    ///
    /// If the ACME server does not implement [pre-authorization], it MUST omit the `newAuthz` field
    /// of the directory.
    ///
    /// [pre-authorization]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.4.1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_authz: Option<String>,

    /// URL for certificate revocation requests.
    pub revoke_cert: String,

    /// URL for key change requests.
    pub key_change: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ApiDirectoryMeta>,
}

/// <https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.6>
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiDirectoryMeta {
    /// URL identifying the current terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,

    /// URL locating a website providing more information about the ACME server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    /// The hostnames that the ACME server recognizes as referring to itself for the purposes of
    /// Certification Authority Authorization (CAA) record validation as defined in [RFC 6844].
    ///
    /// [RFC 6844]: https://datatracker.ietf.org/doc/html/rfc6844
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa_identities: Option<Vec<String>>,

    /// If true, then the CA requires that all newAccount requests include an
    /// `externalAccountBinding` field associating the new account with an external account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_required: Option<bool>,
}

impl ApiDirectoryMeta {
    pub fn external_account_required(&self) -> bool {
        self.external_account_required.unwrap_or(false)
    }
}

/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2>
//
//    {
//      "status": "valid",
//      "contact": [
//        "mailto:cert-admin@example.com",
//        "mailto:admin@example.com"
//      ],
//      "termsOfServiceAgreed": true,
//      "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
//    }
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub orders: Option<String>,
}

impl ApiAccount {
    pub fn is_status_valid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("valid")
    }

    pub fn is_status_deactivated(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("deactivated")
    }

    pub fn is_status_revoked(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("revoked")
    }

    pub fn terms_of_service_agreed(&self) -> bool {
        self.terms_of_service_agreed.unwrap_or(false)
    }
}

/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3>
// {
//   "status": "pending",
//   "expires": "2019-01-09T08:26:43.570360537Z",
//   "identifiers": [
//     {
//       "type": "dns",
//       "value": "acmetest.algesten.se"
//     }
//   ],
//   "authorizations": [
//     "https://example.com/acme/authz/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs"
//   ],
//   "finalize": "https://example.com/acme/finalize/7738992/18234324"
// }
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    pub identifiers: Vec<ApiIdentifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub error: Option<ApiProblem>,
    pub authorizations: Option<Vec<String>>,
    pub finalize: String,
    pub certificate: Option<String>,
}

impl ApiOrder {
    pub(crate) fn from_identifiers(identifiers: Vec<ApiIdentifier>) -> Self {
        Self {
            identifiers,
            ..Default::default()
        }
    }

    /// Returns true as long as there are outstanding authorizations.
    pub fn is_status_pending(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("pending")
    }

    /// Returns true if all authorizations are finished, and we need to call "finalize".
    pub fn is_status_ready(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("ready")
    }

    /// Returns true during "finalize", when the server is processing our CSR.
    pub fn is_status_processing(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("processing")
    }

    /// Returns true if the certificate is issued and can be downloaded.
    pub fn is_status_valid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("valid")
    }

    /// Returns true if the order failed and can't be used again.
    pub fn is_status_invalid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("invalid")
    }

    /// Returns all domains.
    pub fn domains(&self) -> Vec<&str> {
        self.identifiers
            .iter()
            .map(|identifier| identifier.value.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiIdentifier {
    #[serde(rename = "type")]
    pub _type: String,
    pub value: String,
}

impl ApiIdentifier {
    pub(crate) fn dns(value: &str) -> Self {
        Self {
            _type: "dns".to_owned(),
            value: value.to_owned(),
        }
    }

    pub fn is_type_dns(&self) -> bool {
        self._type == "dns"
    }
}

// {
//   "identifier": {
//     "type": "dns",
//     "value": "acmetest.algesten.se"
//   },
//   "status": "pending",
//   "expires": "2019-01-09T08:26:43Z",
//   "challenges": [
//     {
//       "type": "http-01",
//       "status": "pending",
//       "url": "https://example.com/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789597",
//       "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
//     },
//     {
//       "type": "tls-alpn-01",
//       "status": "pending",
//       "url": "https://example.com/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789598",
//       "token": "WCdRWkCy4THTD_j5IH4ISAzr59lFIg5wzYmKxuOJ1lU"
//     },
//     {
//       "type": "dns-01",
//       "status": "pending",
//       "url": "https://example.com/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789599",
//       "token": "RRo2ZcXAEqxKvMH8RGcATjSK1KknLEUmauwfQ5i3gG8"
//     }
//   ]
// }
//
// on incorrect challenge, something like:
//
//   "challenges": [
//     {
//       "type": "dns-01",
//       "status": "invalid",
//       "error": {
//         "type": "urn:ietf:params:acme:error:dns",
//         "detail": "DNS problem: NXDOMAIN looking up TXT for _acme-challenge.martintest.foobar.com",
//         "status": 400
//       },
//       "url": "https://example.com/acme/challenge/afyChhlFB8GLLmIqEnqqcXzX0Ss3GBw6oUlKAGDG6lY/221695600",
//       "token": "YsNqBWZnyYjDun3aUC2CkCopOaqZRrI5hp3tUjxPLQU"
//     },
// "Incorrect TXT record \"caOh44dp9eqXNRkd0sYrKVF8dBl0L8h8-kFpIBje-2c\" found at _acme-challenge.martintest.foobar.com
/// An ACME authorization object.
///
/// Represents a server's authorization for an account to represent an identifier.
///
/// See [RFC 8555 §7.1.4].
///
/// [RFC 8555 §7.1.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiAuthorization {
    /// Authorization identifier.
    pub identifier: ApiIdentifier,

    /// Authorization status.
    pub status: AuthorizationStatus,

    /// The timestamp after which the server will consider this authorization invalid.
    ///
    /// Uses RFC 3339 format.
    ///
    /// This field is required for objects with "valid" in the "status" field.
    pub expires: Option<String>,

    /// Returns the challenges related to the identifier.
    ///
    /// - For pending authorizations, the challenges that the client can fulfill in order to prove
    ///   possession of the identifier.
    /// - For valid authorizations, the challenge that was validated.
    /// - For invalid authorizations, the challenge that was attempted and failed.
    ///
    /// Each array entry is an object with parameters required to validate the challenge. A client
    /// should attempt to fulfill one of these challenges, and a server should consider any one of
    /// the challenges sufficient to make the authorization valid.
    pub challenges: Vec<ApiChallenge>,

    /// This field MUST be present and true for authorizations created as a result of a newOrder
    /// request containing a DNS identifier with a value that was a wildcard domain name. For other
    /// authorizations, it MUST be absent. Wildcard domain names are described in §7.1.3.
    pub wildcard: Option<bool>,
}

/// The status of an [`ApiAuthorization`].
///
/// See [RFC 8555 §7.1.4].
///
/// [RFC 8555 §7.1.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl ApiAuthorization {
    /// Returns true if authorization was created for a wildcard domain.
    pub fn is_wildcard(&self) -> bool {
        self.wildcard.unwrap_or(false)
    }

    /// Returns an `http-01` challenge, if one is present.
    pub fn http_challenge(&self) -> Option<&ApiChallenge> {
        self.challenges.iter().find(|c| c._type == "http-01")
    }

    /// Returns a `dns-01` challenge, if one is present.
    pub fn dns_challenge(&self) -> Option<&ApiChallenge> {
        self.challenges.iter().find(|c| c._type == "dns-01")
    }

    /// Returns a `tls-alpn-01` challenge, if one is present.
    pub fn tls_alpn_challenge(&self) -> Option<&ApiChallenge> {
        self.challenges.iter().find(|c| c._type == "tls-alpn-01")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiChallenge {
    pub url: String,
    #[serde(rename = "type")]
    pub _type: String,
    pub status: String,
    pub token: String,
    pub validated: Option<String>,
    pub error: Option<ApiProblem>,
}

// {
//   "type": "http-01",
//   "status": "pending",
//   "url": "https://acme-staging-v02.api.letsencrypt.org/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789597",
//   "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
// }
impl ApiChallenge {
    /// Returns true if challenge status is "pending".
    pub fn is_status_pending(&self) -> bool {
        &self.status == "pending"
    }

    /// Returns true if challenge status is "processing".
    pub fn is_status_processing(&self) -> bool {
        &self.status == "processing"
    }

    /// Returns true if challenge status is "valid".
    pub fn is_status_valid(&self) -> bool {
        &self.status == "valid"
    }

    /// Returns true if challenge status is "invalid".
    pub fn is_status_invalid(&self) -> bool {
        &self.status == "invalid"
    }
}

/// See <https://datatracker.ietf.org/doc/html/rfc8555#section-7.4>.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiFinalize {
    /// Certificate Signing Request (CSR) in base64url-encoded DER.
    ///
    /// Note: not PEM, since headers are omitted.
    pub csr: String,
}

/// See <https://datatracker.ietf.org/doc/html/rfc8555#section-7.6>.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRevocation {
    /// The certificate to be revoked, in the base64url-encoded version of the DER format.
    ///
    /// Note: not PEM, since headers are omitted.
    pub certificate: String,

    /// One of the revocation reasonCodes defined in [RFC 5280 §5.3.1].
    ///
    /// [RFC 5280 §5.3.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<usize>,
}

impl ApiRevocation {
    pub fn new(certificate: String, reason: Option<usize>) -> Self {
        Self {
            certificate,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_empty_string() {
        let x = serde_json::to_string(&ApiEmptyString).unwrap();
        assert_eq!("\"\"", x);
    }

    #[test]
    fn test_api_empty_object() {
        let x = serde_json::to_string(&ApiEmptyObject).unwrap();
        assert_eq!("{}", x);
    }
}
