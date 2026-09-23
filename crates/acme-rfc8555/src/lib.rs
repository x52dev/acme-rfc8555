//! Provisioning certificates from ACME (Automatic Certificate Management Environment) providers
//! such as [Let's Encrypt](https://letsencrypt.org/).
//!
//! It follows the [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) spec, using ACME v2 to
//! issue and manage certificates.
//!
//! # Usage
//!
//! Import this crate as `acme`. Network operations are asynchronous and require a Tokio runtime.
//!
//! Start by fetching a [`Directory`] and registering an [`Account`]. Registration sends agreement
//! to the provider's terms of service. Review those terms before registering.
//!
//! ```no_run
//! use acme::{Directory, DirectoryUrl};
//!
//! # async fn example() -> eyre::Result<()> {
//! let directory = Directory::fetch(DirectoryUrl::LetsEncryptStaging).await?;
//! let account = directory
//!     .register_account(Some(vec!["mailto:admin@example.com".to_owned()]))
//!     .await?;
//!
//! // Store this secret securely so that you can load the same account later.
//! let account_key = account.acme_private_key_pem()?;
//! let order = account.new_order("example.com", &["www.example.com"]).await?;
//! # Ok(())
//! # }
//! ```
//!
//! To issue a certificate:
//!
//! 1. Create an order with [`Account::new_order`].
//! 2. Fetch its [`authorizations`]. For each authorization that needs a challenge, choose an
//!    available challenge and publish its proof through your HTTP server, DNS server, or TLS server.
//!    This crate provides the proof data; your application must make it available to the provider.
//! 3. Call [`order::Challenge::validate`] after the proof is available.
//! 4. Call [`order::NewOrder::refresh`] to update the order status, then use
//!    [`order::NewOrder::confirm_validations`] to obtain a [`order::CsrOrder`] when ready.
//! 5. Supply a certificate key to [`order::CsrOrder::finalize`], then call
//!    [`order::CertOrder::download_cert`] to retrieve the certificate and its private key.
//!
//! Certificate keys currently use P-256. Generate one with [`create_p256_key`] or import an existing
//! PKCS#8 PEM key with [`PrivateKey::from_pkcs8_pem`]. The certificate key is separate from the account
//! key used to sign ACME requests.
//!
//! ## Account and certificate storage
//!
//! This crate does not persist accounts or certificates. Store the account key returned by
//! [`Account::acme_private_key_pem`] and use [`Directory::load_existing_account`] to resume work with
//! that account. Use the same provider directory when loading it.
//!
//! Store both [`Certificate::certificate`] and [`Certificate::private_key`] after issuance.
//! Protect private keys from unauthorized access. A later process can load the saved PEM data with
//! [`Certificate::parse`].
//!
//! ## Examples
//!
//! Complete usage examples are provided in the source repository for these challenge types:
//!
//! - [`tls-alpn-01` &rarr;](https://github.com/x52dev/acme-rfc8555/blob/main/examples/tls-alpn-01.rs)
//! - [`http-01` &rarr;](https://github.com/x52dev/acme-rfc8555/blob/main/examples/http-01.rs)
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
    cert::{create_p256_key, Certificate, PrivateKey},
    dir::{Directory, DirectoryUrl},
};
