<h1 align="center">cauteum-proxy</h1>

<p align="center">
  <strong>Egress proxy for sandboxes</strong><br>
  CONNECT + L7 terminate, secret rewrite, policy.local advisor, middleware pipeline.
</p>
<p align="center">
  <a href="https://github.com/cautem/cauteum-proxy/actions/workflows/ci.yml"><img src="https://github.com/cautem/cauteum-proxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/cautem/cauteum-proxy"><img src="https://pkg.go.dev/badge/github.com/cautem/cauteum-proxy.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cautem/cauteum-proxy"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/cautem">cauteum / cauteum</a> ecosystem</sub>
</p>

---

## Overview

The [policy guide](https://cautem.github.io/cauteum-haven.github.io/guides/policy/) covers egress rules; the [security reference](https://cautem.github.io/cauteum-haven.github.io/concepts/security/) records current limits.

**cauteum-proxy** is the mandatory egress sidecar for cauteum sandboxes. It enforces policy at L4/L7, rewrites credential placeholders, emits OCSF audit lines, and exposes `policy.local` for in-sandbox proposals.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **L4** | CONNECT allowlist from `cauteum-core` engine |
| **L7** | TLS terminate for REST / GraphQL / MCP rules |
| **Secrets** | Placeholder rewrite + gateway secret refresh |
| **Advisor** | `https://policy.local/v1/{policy,denials,proposals}` |
| **Hot reload** | Watch policy file; Apply under RWMutex |

---

## Installation

Use the sibling `go.work` workspace for source builds and run `go test ./...` in this checkout. Published alpha dependencies have not passed a standalone consumer build.

Usually run as the sandbox sidecar (started by `cauteum-driver`), not as a standalone service.

**Requirements:** Go 1.27+

---

## Quick Start

```bash
# From the CLI (host-side debug proxy):
cauteum proxy --listen 127.0.0.1:3128 --policy ./policy.yaml
```

---

## Package Structure

| Path | Purpose |
|------|---------|
| `proxy/` | Server, MITM, audit, policy.local |
| `proxy/middleware/` | Request pipeline hooks |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/cautem](https://github.com/cautem) |
| Organization overview | [github.com/cautem](https://github.com/cautem) |
| pkg.go.dev | [`github.com/cautem/cauteum-proxy`](https://pkg.go.dev/github.com/cautem/cauteum-proxy) |

## License

[Apache-2.0](./LICENSE) © cauteum
