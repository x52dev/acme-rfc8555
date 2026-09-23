use serde::{Deserialize, Serialize};

use crate::api;

/// The status of an [`api::Authorization`].
///
/// See [RFC 8555 §7.1.6].
///
/// [RFC 8555 §7.1.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// An ACME challenge object.
///
/// Represents a server's offer to validate a client's possession of an identifier in a specific
/// way.
///
/// See [RFC 8555 §7.1.5].
///
/// # Example JSON
///
/// ```json
/// {
///   "type": "http-01",
///   "status": "pending",
///   "url": "https://acme-staging-v02.api.letsencrypt.org/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789597",
///   "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
/// }
/// ```
///
/// [RFC 8555 §7.1.5]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// Type of challenge encoded in the object.
    #[serde(rename = "type")]
    pub _type: String,

    /// URL to which a response can be posted.
    pub url: String,

    /// Status of this challenge.
    pub status: ChallengeStatus,

    /// Time at which the server validated this challenge.
    ///
    /// Uses RFC 3339 format.
    pub validated: Option<String>,

    /// Error that occurred while the server was validating the challenge, if any.
    pub error: Option<api::Problem>,

    pub token: String,
}
