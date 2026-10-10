# Roadmap — cautem-proxy

Status: **v0.1.6** (stable numbered release) · Depends on core `v0.1.6`; slogx `v0.1.2`

## This module

| ID | Item | Notes |
|----|------|-------|
| X1 | **JWT verify** | Cryptographic JWKS/HMAC before credential rewrite |
| X2 | **Secret backends** | Bridge Vault/cloud SM into sidecar `SecretStore` |
| X3 | **policy.local ↔ gateway** | Reliable proposal sync when gateway is present |
| X4 | **MCP terminate** | Policy-aware MCP frames |

## Release

Requires cautem-core `v0.1.0-alpha.1` · tagged after core in the cascade.
