# `acme-lite`

> Provision certificates from ACME (Automatic Certificate Management Environment) providers such as [Let's Encrypt](https://letsencrypt.org/).

<!-- prettier-ignore-start -->

[![crates.io](https://img.shields.io/crates/v/acme-lite?label=latest)](https://crates.io/crates/acme-lite)
[![Documentation](https://docs.rs/acme-lite/badge.svg)](https://docs.rs/acme-lite/0.0.2)
![MIT or Apache 2.0 licensed](https://img.shields.io/crates/l/acme-lite.svg)
<br />
[![dependency status](https://deps.rs/crate/acme-lite/0.0.2/status.svg)](https://deps.rs/crate/acme-lite/0.0.2)
[![Download](https://img.shields.io/crates/d/acme-lite.svg)](https://crates.io/crates/acme-lite)
[![CI](https://github.com/x52dev/acme-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/x52dev/acme-lite/actions/workflows/ci.yml)

<!-- prettier-ignore-end -->

Follows the [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) spec, using ACME v2 to issue/renew certificates.

Originally a fork of [acme-micro](https://github.com/kpcyrd/acme-micro) and [acme-lib](https://github.com/algesten/acme-lib), but the code has deviated significantly since then.

## Crate Goals

- [x] No OpenSSL
- [x] RFC 8555 compliance
- [ ] Full documentation
- [ ] Full test suite
- [ ] Support multiple certificate key types

## Domain Ownership

Most website TLS certificates tries to prove ownership/control over the domain they are issued for. For ACME, this means proving you control either:

- a server answering TLS or HTTP requests for that domain;
- the DNS server answering name lookups against the domain.

To use this library, there are points in the flow where you would need to modify either the web server or DNS server before progressing to get the certificate.

See [`tls_alpn_challenge`], [`http_challenge`], and [`dns_challenge`].

### Multiple Domains

When creating a new order, it's possible to provide multiple alt-names that will also be part of the certificate. The ACME API requires you to prove ownership of each such domain. See [`authorizations`].

## Rate Limits

The ACME API provider Let's Encrypt uses [rate limits] to ensure the API is not being abused. It might be tempting to put the `delay` really low in some of this library's polling calls, but balance this against the real risk of having access cut off.

## Use Staging For Development!

Especially take care to use the Let's Encrypt staging environment for development where the rate limits are more relaxed. See [`DirectoryUrl::LetsEncryptStaging`].

[`http_challenge`]: https://docs.rs/acme-lite/0.0.2/acme_lite/order/struct.Auth.html#method.http_challenge
[`dns_challenge`]: https://docs.rs/acme-lite/0.0.2/acme_lite/order/struct.Auth.html#method.dns_challenge
[`tls_alpn_challenge`]: https://docs.rs/acme-lite/0.0.2/acme_lite/order/struct.Auth.html#method.tls_alpn_challenge
[`authorizations`]: https://docs.rs/acme-lite/0.0.2/acme_lite/order/struct.NewOrder.html#method.authorizations
[rate limits]: https://letsencrypt.org/docs/rate-limits
[`DirectoryUrl::LetsEncryptStaging`]: https://docs.rs/acme-lite/0.0.2/acme_lite/enum.DirectoryUrl.html#variant.LetsEncryptStaging
