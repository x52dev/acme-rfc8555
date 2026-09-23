use serde::{Deserialize, Serialize};

use crate::api;

/// The status of an [`api::Authorization`].
///
/// See [RFC 8555 §7.1.3].
///
/// [RFC 8555 §7.1.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// An ACME order object.
///
/// Represents a client's request for a certificate and is used to track the progress of that order
/// through to issuance.
///
/// See [RFC 8555 §7.1.3].
///
/// [RFC 8555 §7.1.3]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3
///
/// # Example JSON
///
/// ```json
/// {
///   "status": "pending",
///   "expires": "2019-01-09T08:26:43.570360537Z",
///   "identifiers": [
///     {
///       "type": "dns",
///       "value": "acmetest.algesten.se"
///     }
///   ],
///   "authorizations": [
///     "https://example.com/acme/authz/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs"
///   ],
///   "finalize": "https://example.com/acme/finalize/7738992/18234324"
/// }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<OrderStatus>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    pub identifiers: Vec<api::Identifier>,

    ///
    ///
    /// Uses RFC 3339 format.
    pub not_before: Option<String>,

    ///
    ///
    /// Uses RFC 3339 format.
    pub not_after: Option<String>,

    pub error: Option<api::Problem>,
    pub authorizations: Option<Vec<String>>,
    pub finalize: String,
    pub certificate: Option<String>,
}

impl Order {
    pub(crate) fn from_identifiers(identifiers: Vec<api::Identifier>) -> Self {
        Self {
            identifiers,
            ..Default::default()
        }
    }

    /// Returns all domains associated with this order.
    pub fn domains(&self) -> Vec<&str> {
        self.identifiers
            .iter()
            .map(|identifier| identifier.value.as_str())
            .collect()
    }

    /// Let's Encrypt was observed to return domains in alternate order which may flip primary with
    /// SAN(s).
    ///
    /// This overwrites self without changing the order of the domains.
    pub(crate) fn overwrite(&mut self, mut from_api: Self) -> eyre::Result<()> {
        // Make sure the lists are the same.
        if from_api.identifiers.len() != self.identifiers.len()
            || from_api
                .identifiers
                .iter()
                .any(|id| !self.identifiers.contains(id))
        {
            return Err(eyre::eyre!(
                "Order domain(s) mismatch: had {:?} and got {:?}",
                self.identifiers,
                from_api.identifiers
            ));
        }

        // Then preserve the original order.
        from_api.identifiers = std::mem::take(&mut self.identifiers);
        *self = from_api;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_preserves_requested_domain_order() {
        let first = api::Identifier::dns("example.com");
        let second = api::Identifier::dns("www.example.com");
        let mut order = Order::from_identifiers(vec![first.clone(), second.clone()]);
        let refreshed = Order {
            status: Some(OrderStatus::Ready),
            identifiers: vec![second, first],
            ..Default::default()
        };

        order.overwrite(refreshed).unwrap();

        assert_eq!(order.domains(), ["example.com", "www.example.com"]);
        assert_eq!(order.status, Some(OrderStatus::Ready));
    }

    #[test]
    fn overwrite_rejects_changed_domains_without_mutating_order() {
        let mut order = Order::from_identifiers(vec![api::Identifier::dns("example.com")]);
        let original = order.clone();
        let refreshed = Order::from_identifiers(vec![api::Identifier::dns("other.example.com")]);

        assert!(order.overwrite(refreshed).is_err());
        assert_eq!(order, original);
    }

    #[test]
    fn overwrite_rejects_missing_domains_without_mutating_order() {
        let mut order = Order::from_identifiers(vec![
            api::Identifier::dns("example.com"),
            api::Identifier::dns("www.example.com"),
        ]);
        let original = order.clone();
        let refreshed = Order::from_identifiers(vec![api::Identifier::dns("example.com")]);

        assert!(order.overwrite(refreshed).is_err());
        assert_eq!(order, original);
    }
}
