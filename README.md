# `acme-rfc8555`

> Provision certificates from ACME (Automatic Certificate Management Environment) providers such as [Let's Encrypt](https://letsencrypt.org/).

<!-- prettier-ignore-start -->

[![crates.io](https://img.shields.io/crates/v/acme-rfc8555?label=latest)](https://crates.io/crates/acme-rfc8555)
[![Documentation](https://docs.rs/acme-rfc8555/badge.svg)](https://docs.rs/acme-rfc8555/0.1.2)
![MIT or Apache 2.0 licensed](https://img.shields.io/crates/l/acme-rfc8555.svg)
<br />
[![CI](https://github.com/x52dev/acme-rfc8555/actions/workflows/ci.yml/badge.svg)](https://github.com/x52dev/acme-rfc8555/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/x52dev/acme-rfc8555/branch/main/graph/badge.svg)](https://codecov.io/gh/x52dev/acme-rfc8555)
[![dependency status](https://deps.rs/crate/acme-rfc8555/0.1.2/status.svg)](https://deps.rs/crate/acme-rfc8555/0.1.2)
[![Download](https://img.shields.io/crates/d/acme-rfc8555.svg)](https://crates.io/crates/acme-rfc8555)

<!-- prettier-ignore-end -->

Follows the [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) spec, using ACME v2 to issue and manage certificates.

Originally a fork of [acme-micro](https://github.com/kpcyrd/acme-micro) and [acme-lib](https://github.com/algesten/acme-lib), but the code has deviated significantly since then.

## Crate Goals

- [x] No OpenSSL
- [x] RFC 8555 compliance
- [ ] Full documentation
- [ ] Full test suite
- [ ] Support multiple certificate key types

## Documentation

All documentation is provided [via docs.rs](https://docs.rs/acme-rfc8555).
