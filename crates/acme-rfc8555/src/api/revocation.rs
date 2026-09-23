use serde::{Deserialize, Serialize};

/// Certificate revocation request.
///
/// See [RFC 8555 §7.6].
///
/// [RFC 8555 §7.6]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.6
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
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

impl Revocation {
    pub fn new(certificate: String, reason: Option<usize>) -> Self {
        Self {
            certificate,
            reason,
        }
    }
}
