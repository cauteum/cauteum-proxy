package proxy

import (
	"strings"
	"testing"
)

func TestFormatOCSF_NetAllowDeny(t *testing.T) {
	allow := formatOCSF(auditEvent{
		TS: "2026-04-01T04:04:32.118Z", Action: "allow", Host: "api.github.com", Port: 443,
		Binary: "/usr/bin/curl", Allow: true, Reason: "policy:github_api",
	})
	if !strings.Contains(allow, "OCSF NET:OPEN [INFO] ALLOWED /usr/bin/curl -> api.github.com:443") {
		t.Fatalf("allow=%q", allow)
	}
	if !strings.Contains(allow, "[reason:policy:github_api]") {
		t.Fatalf("missing reason: %q", allow)
	}

	deny := formatOCSF(auditEvent{
		TS: "2026-04-01T04:04:32.690Z", Action: "deny", Host: "httpbin.org", Port: 443,
		Binary: "/usr/bin/curl", Allow: false, Reason: "no matching policy",
	})
	if !strings.Contains(deny, "OCSF NET:OPEN [MED] DENIED") {
		t.Fatalf("deny=%q", deny)
	}
	if !strings.Contains(deny, "[reason:no matching policy]") {
		t.Fatalf("missing reason: %q", deny)
	}
}

func TestFormatOCSF_HTTP(t *testing.T) {
	line := formatOCSF(auditEvent{
		TS: "2026-04-01T04:04:32.190Z", Action: "allow", Host: "api.github.com", Port: 443,
		Method: "GET", Path: "/zen", Allow: true, Reason: "policy:github_api",
	})
	if !strings.Contains(line, "OCSF HTTP:GET [INFO] ALLOWED GET https://api.github.com/zen") {
		t.Fatalf("http=%q", line)
	}
}

func TestFormatOCSF_Reload(t *testing.T) {
	line := formatOCSF(auditEvent{
		TS: "2026-04-01T04:04:32.190Z", Action: "reload", Allow: true,
		Reason: "policy reloaded from /policy.yaml",
	})
	if !strings.Contains(line, "OCSF CONFIG:LOADED [INFO] LOADED policy reloaded from /policy.yaml") {
		t.Fatalf("reload=%q", line)
	}
}

func TestFormatOCSF_AuditMode(t *testing.T) {
	line := formatOCSF(auditEvent{
		TS: "t", Action: "audit", Host: "example.com", Port: 443,
		Allow: true, Reason: "would deny", Binary: "curl",
	})
	if !strings.Contains(line, "ALLOWED") || !strings.Contains(line, "enforcement:audit") {
		t.Fatalf("audit mode=%q", line)
	}
}

func TestFormatOCSFRedactsPathAndReason(t *testing.T) {
	line := formatOCSF(auditEvent{
		TS: "t", Action: "deny", Host: "example.com", Port: 443,
		Method: "GET", Path: "/search?q=private-value", Reason: "authorization=secret-value",
	})
	if strings.Contains(line, "private-value") || strings.Contains(line, "secret-value") {
		t.Fatalf("audit leaked secret: %s", line)
	}
	if !strings.Contains(line, "/search?[REDACTED]") {
		t.Fatalf("audit lost useful path: %s", line)
	}
}
