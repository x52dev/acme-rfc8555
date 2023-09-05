use serde::{Deserialize, Serialize};

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
pub struct Directory {
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
    pub meta: Option<DirectoryMeta>,
}

/// <https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.6>
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
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

impl DirectoryMeta {
    pub fn external_account_required(&self) -> bool {
        self.external_account_required.unwrap_or(false)
    }
}
