# Changelog

## Unreleased

- Ensure domains remain in original order throughout processing.
- Built-in HTTP client now uses `rustls` and `webpki-roots` by default. Disable default features to regain control `reqwest`'s crate features.

## 0.1.0

- Initial release.
