use serde::{Deserialize, Serialize};

/// Finalized order containing signed CSR.
///
/// See [RFC 8555 §7.4].
///
/// [RFC 8555 §7.4]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finalize {
    /// Certificate Signing Request (CSR) in base64url-encoded DER.
    ///
    /// Note: not PEM, since headers are omitted.
    pub csr: String,
}

impl Finalize {
    /// Constructs new finalize request from CSR.
    pub(crate) fn new(csr: String) -> Self {
        Self { csr }
    }
}
