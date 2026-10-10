# Changelog

## [Unreleased]

## [v0.1.6] - 2026-10-11

### Changed

- Rename the module, runtime identifiers and project references to the `cautem` namespace.

## [v0.1.0-beta.2] - 2026-10-10

### Fixed

- Reject malformed egress CA bundles before the proxy starts instead of silently falling back to a different trust configuration.
- Bound and cancel upstream HTTP proxy CONNECT handshakes.
- Send the actual HTTP or WebSocket scheme to supervisor middleware.

### Changed

- Complete the cautem rebrand and align CI with Go 1.27.2.
- Resolve `cautem-core` v0.1.0-beta.2 and `slogx` v0.1.0-beta.1 from published tags.

## [v0.1.0-beta.1] - 2026-10-07

### Added

- Add structured lifecycle logs for proxy operations.

### Changed

- Use `cautem-core` v0.1.0-beta.1.

### Fixed

- Keep Unix-only workload socket coverage out of cross-platform test builds.

## [v0.1.0-alpha.2] - 2026-10-07

### Added

- Enforce HTTP query, JSON-RPC, GraphQL, and MCP policy selectors in the proxy data path.
- Add gRPC supervisor middleware, OpenShell credential binding, and supported token-grant runtime flows.
- Add structured `no_proxy` handling and bounded protocol, relay, and audit operations.

### Changed

- Use the published core and slogx alpha.2 modules; update SPIFFE, go-jose, and gRPC dependencies.
- Distribute the module under Apache-2.0 while retaining the pinned OpenShell SDK revision for protocol compatibility.

### Security

- Fail closed on unresolved credential bindings, malformed protocol requests, and unsafe upstream destinations.
- Serialize audit output from concurrent request handlers to keep records intact.

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- SSRF checks use a single DNS resolve with private-range blocking; loopback bypass is test-only.
- MITM leaf cache is LRU-bounded and re-issues before expiry.
- Audit OCSF details redact URL query values and inline credentials via slogx.
- Corp upstream proxy dials are marked in audit as a trusted boundary.

### Fixed

- Policy watch compares SHA-256 content and updates the hash only after a successful apply.
