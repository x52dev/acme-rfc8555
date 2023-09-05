use serde::{Deserialize, Serialize};

/// An ACME account resource.
///
/// Represents a set of metadata associated with an account.
///
/// See [RFC 8555 §7.1.2].
///
/// # Example JSON
///
/// ```json
/// {
///   "status": "valid",
///   "contact": [
///     "mailto:cert-admin@example.com",
///     "mailto:admin@example.com"
///   ],
///   "termsOfServiceAgreed": true,
///   "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
/// }
/// ```
///
/// [RFC 8555 §7.1.2]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
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

impl Account {
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
