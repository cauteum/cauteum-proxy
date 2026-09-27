# Changelog

## [Unreleased]

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- SSRF checks use a single DNS resolve with private-range blocking; loopback bypass is test-only.
- MITM leaf cache is LRU-bounded and re-issues before expiry.
- Audit OCSF details redact URL query values and inline credentials via slogx.
- Corp upstream proxy dials are marked in audit as a trusted boundary.

### Fixed

- Policy watch compares SHA-256 content and updates the hash only after a successful apply.
