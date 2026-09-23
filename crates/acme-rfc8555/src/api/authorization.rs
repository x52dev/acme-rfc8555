use serde::{Deserialize, Serialize};

use crate::api;

/// The status of an [`api::Order`].
///
/// See [RFC 8555 §7.1.4].
///
/// [RFC 8555 §7.1.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4
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
pub struct Authorization {
    /// Authorization identifier.
    pub identifier: api::Identifier,

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
    pub challenges: Vec<api::Challenge>,

    /// This field MUST be present and true for authorizations created as a result of a newOrder
    /// request containing a DNS identifier with a value that was a wildcard domain name. For other
    /// authorizations, it MUST be absent. Wildcard domain names are described in §7.1.3.
    pub wildcard: Option<bool>,
}

impl Authorization {
    /// Returns true if authorization was created for a wildcard domain.
    pub fn is_wildcard(&self) -> bool {
        self.wildcard.unwrap_or(false)
    }

    /// Returns an `http-01` challenge, if one is present.
    pub fn http_challenge(&self) -> Option<&api::Challenge> {
        self.challenges.iter().find(|c| c._type == "http-01")
    }

    /// Returns a `dns-01` challenge, if one is present.
    pub fn dns_challenge(&self) -> Option<&api::Challenge> {
        self.challenges.iter().find(|c| c._type == "dns-01")
    }

    /// Returns a `tls-alpn-01` challenge, if one is present.
    pub fn tls_alpn_challenge(&self) -> Option<&api::Challenge> {
        self.challenges.iter().find(|c| c._type == "tls-alpn-01")
    }
}
