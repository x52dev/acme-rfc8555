# acme-lite

acme-lite is a fork of [acme-micro](https://github.com/kpcyrd/acme-micro) and [acme-lib](https://github.com/algesten/acme-lib) and facilitates provisioning certificates from ACME (Automatic Certificate Management Environment) services such as [Let's Encrypt](https://letsencrypt.org/).

It follows the [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) spec, using ACME v2 to issue/renew certificates.

### Domain ownership

Most website TLS certificates tries to prove ownership/control over the domain they are issued for. For ACME, this means proving you control either a web server answering HTTP requests to the domain, or the DNS server answering name lookups against the domain.

To use this library, there are points in the flow where you would need to modify either the web server or DNS server before progressing to get the certificate.

See [`http_challenge`] and [`dns_challenge`].

#### Multiple domains

When creating a new order, it's possible to provide multiple alt-names that will also be part of the certificate. The ACME API requires you to prove ownership of each such domain. See [`authorizations`].

[`http_challenge`]: https://docs.rs/acme-lite/0.12/acme_lite/order/struct.Auth.html#method.http_challenge
[`dns_challenge`]: https://docs.rs/acme-lite/0.12/acme_lite/order/struct.Auth.html#method.dns_challenge
[`authorizations`]: https://docs.rs/acme-lite/0.12/acme_lite/order/struct.NewOrder.html#method.authorizations

## Rate limits

The ACME API provider Let's Encrypt uses [rate limits] to ensure the API I not being abused. It might be tempting to put the `delay` really low in some of this libraries' polling calls, but balance this against the real risk of having access cut off.

[rate limits]: https://letsencrypt.org/docs/rate-limits/

### Use staging for development!

Especially take care to use the Let's Encrypt staging environment for development where the rate limits are more relaxed. See `DirectoryUrl::LetsEncryptStaging`.
