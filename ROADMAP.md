# Roadmap — cauteum-proxy

Status: **v0.1.0-alpha.1** (alpha) · Depends on [cauteum-core](https://github.com/cauteum-haven/cauteum-core) `v0.1.0-alpha.1`

## This module

| ID | Item | Notes |
|----|------|-------|
| X1 | **JWT verify** | Cryptographic JWKS/HMAC before credential rewrite (hub R8) |
| X2 | **Secret backends** | Bridge Vault/cloud SM into sidecar `SecretStore` (hub R3) |
| X3 | **policy.local ↔ gateway** | Reliable proposal sync when gateway is present |
| X4 | **MCP terminate** | Policy-aware MCP frames (hub R5) |

## Release

Requires cauteum-core `v0.1.0-alpha.1` · tagged after core in the cascade.
