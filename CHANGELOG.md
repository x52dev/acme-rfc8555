# Changelog

## Unreleased

## 0.2.0

- Correctly handle certificate chains in `Certificate::valid_days_left()`.

## 0.1.2

- Update `reqwest` dependency to `0.12`.
- Minimum supported Rust version (MSRV) is now 1.72.

## 0.1.1

- Ensure domains remain in original order throughout processing.
- Built-in HTTP client now uses `rustls` and `webpki-roots` by default. Disable default features to regain control `reqwest`'s crate features.

## 0.1.0

- Initial release.
