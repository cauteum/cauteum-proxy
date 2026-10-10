// Package proxy implements mandatory egress (CONNECT + HTTP L7 + TLS terminate).
// Process logs use github.com/cauteum-haven/slogx via cauteum-runtime/internal/logging when wired
// by the CLI/sidecar entrypoint (App.Proxy); audit lines remain OCSF shorthand
// on the audit writer.
package proxy
