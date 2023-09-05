//! Provisioning certificates from ACME (Automatic Certificate Management Environment) providers
//! such as [Let's Encrypt](https://letsencrypt.org/).
//!
//! It follows the [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) spec, using ACME v2 to
//! issue/renew certificates.
//!
//! # Usage
//!
//! - TODO
//!
//! ## Examples
//!
//! Complete usage examples are provided in the source repository for these challenge types:
//!
//! - [`tls-alpn-01` &rarr;](https://github.com/x52dev/acme-lite/blob/main/examples/tls-alpn-01.rs)
//! - [`http-01` &rarr;](https://github.com/x52dev/acme-lite/blob/main/examples/http-01.rs)
//!
//! # Domain Ownership
//!
//! Most website TLS certificates tries to prove ownership/control over the domain they are issued
//! for. For ACME, this means proving you control either:
//!
//! - a server answering TLS or HTTP requests for that domain;
//! - the DNS server answering name lookups against the domain.
//!
//! To use this library, there are points in the flow where you would need to modify either the web
//! server or DNS server before progressing to get the certificate.
//!
//! See [`tls_alpn_challenge`], [`http_challenge`], and [`dns_challenge`].
//!
//! ## Multiple Domains
//!
//! When creating a new order, it's possible to provide multiple alt-names that will also be part of
//! the certificate. The ACME API requires you to prove ownership of each such domain. See
//! [`authorizations`].
//!
//! # Rate Limits
//!
//! The ACME API provider Let's Encrypt uses [rate limits] to ensure the API is not being abused. It
//! might be tempting to put the `delay` really low in some of this library's polling calls, but
//! balance this against the real risk of having access cut off.
//!
//! ## Use Staging For Development!
//!
//! Especially take care to use the Let's Encrypt staging environment for development where the rate
//! limits are more relaxed. See [`DirectoryUrl::LetsEncryptStaging`].
//!
//! [`http_challenge`]: crate::order::Auth::http_challenge()
//! [`tls_alpn_challenge`]: crate::order::Auth::tls_alpn_challenge()
//! [`dns_challenge`]: crate::order::Auth::dns_challenge()
//! [`authorizations`]: crate::order::NewOrder::authorizations()
//! [rate limits]: https://letsencrypt.org/docs/rate-limits

#![deny(rust_2018_idioms, nonstandard_style, future_incompatible)]

mod acc;
mod cert;
mod dir;
mod error;
mod jws;
mod req;
mod trans;

pub mod api;
pub mod order;

#[cfg(test)]
mod test;

pub use crate::{
    acc::{Account, RevocationReason},
    cert::{create_p256_key, Certificate},
    dir::{Directory, DirectoryUrl},
};
