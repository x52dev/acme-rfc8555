/*!
`acme-lite` is a library for provisioning certificates from ACME (Automatic Certificate
Management Environment) services such as [Let's Encrypt](https://letsencrypt.org/).

It follows the [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555) spec, using ACME v2 to
issue/renew certificates.

# Example

```no_run
use std::time::Duration;

use acme_lite::{Certificate, Directory, DirectoryUrl, create_p256_key};

# #[tokio::test]
async fn request_cert() -> eyre::Result<Certificate> {
    // Use `DirectoryUrl::LetsEncrypt` for production.
    let url = DirectoryUrl::LetsEncryptStaging;

    // Create a directory entrypoint.
    let dir = Directory::from_url(url).await?;

    // Your contact addresses, note the `mailto:`
    let contact = vec!["mailto:foo@bar.com".to_owned()];

    // Generate a private key and register an account with your ACME provider.
    // You should write it to disk any use `load_account` afterwards.
    let acc = dir.register_account(Some(contact.clone()))?;

    // Example of how to load an account from string:
    let singing_key = acc.acme_private_key_pem()?;
    let acc = dir.load_account(&singing_key, Some(contact))?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order("example.org", &[])?;

    // If the ownership of the domain(s) have already been
    // authorized in a previous order, you might be able to
    // skip validation. The ACME API provider decides.
    let ord_csr = loop {
        // are we done?
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        let auths = ord_new.authorizations()?;

        // For HTTP, the challenge is a text file that needs to
        // be placed in your web server's root:
        //
        // /var/www/.well-known/acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain(s) you are trying to get a
        // certificate for:
        //
        // http://example.org/.well-known/acme-challenge/<token>
        let challenge = auths[0].http_challenge().unwrap();

        // The token is the filename.
        let token = challenge.http_token();
        let path = format!(".well-known/acme-challenge/{token}");

        // The proof is the contents of the file
        let proof = challenge.http_proof()?;

        // Here you must do "something" to place
        // the file/contents in the correct place.
        // update_my_web_server(&path, &proof);

        // After the file is accessible from the web, this tells the ACME API
        // to start checking the existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        challenge.validate(Duration::from_millis(5000))?;

        // Update the state against the ACME API.
        ord_new.refresh()?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let signing_key = create_p256_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr.finalize_signing_key(signing_key, Duration::from_millis(5000)).await?;

    // Now download the certificate. Also stores the cert in
    // the persistence.
    let cert = ord_cert.download_cert().await?;
    println!("{cert:?}");

    Ok(cert)
}
```

## Domain ownership

Most website TLS certificates tries to prove ownership/control over the domain they
are issued for. For ACME, this means proving you control either a web server answering
HTTP requests to the domain, or the DNS server answering name lookups against the domain.

To use this library, there are points in the flow where you would need to modify either
the web server or DNS server before progressing to get the certificate.

See [`http_challenge`] and [`dns_challenge`].

### Multiple domains

When creating a new order, it's possible to provide multiple alt-names that will also
be part of the certificate. The ACME API requires you to prove ownership of each such
domain. See [`authorizations`].

[`http_challenge`]: order::Auth::http_challenge()
[`dns_challenge`]: order::Auth::dns_challenge()
[`authorizations`]: order::NewOrder::authorizations()

## Rate limits

The ACME API provider Let's Encrypt uses [rate limits] to ensure the API i not being
abused. It might be tempting to put the `delay` really low in some of this
libraries' polling calls, but balance this against the real risk of having access
cut off.

[rate limits]: https://letsencrypt.org/docs/rate-limits/

### Use staging for development!

Especially take care to use the Let's Encrypt staging environment for development where the rate
limits are more relaxed. See [`DirectoryUrl::LetsEncryptStaging`].
*/

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
