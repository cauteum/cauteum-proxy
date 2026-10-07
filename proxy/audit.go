package proxy

import (
	"fmt"
	"strings"
	"time"

	"github.com/whaleshell/slogx"
)

// auditEvent is an internal security / lifecycle decision from the proxy.
type auditEvent struct {
	TS       string
	Action   string // allow | deny | audit | reject | error | dial_error | reload
	Host     string
	Port     int
	Method   string
	Path     string
	Binary   string
	Allow    bool
	Reason   string
	ViaProxy bool // dial went through the corp upstream proxy (trusted boundary)
}

func (s *Server) logAudit(ev auditEvent) {
	if s.audit == nil {
		return
	}
	ev.TS = time.Now().UTC().Format(time.RFC3339Nano)
	line := formatOCSF(ev)
	s.auditMu.Lock()
	_, _ = fmt.Fprintln(s.audit, line)
	s.auditMu.Unlock()
	if ev.Action == "deny" || ev.Action == "reject" {
		s.recordDenial(line)
	}
}

// formatOCSF renders NVIDIA OpenShell–compatible OCSF shorthand for agent observation.
// Pattern: <ts> OCSF CLASS:ACTIVITY [SEVERITY] ACTION DETAILS [CONTEXT]
func formatOCSF(ev auditEvent) string {
	ev.Path = slogx.RedactAuditText(ev.Path)
	ev.Reason = slogx.RedactAuditText(ev.Reason)
	class, activity := ocsfClassActivity(ev)
	sev := ocsfSeverity(ev)
	action := ocsfAction(ev)
	details := ocsfDetails(ev)
	ctx := ocsfContext(ev)

	msg := fmt.Sprintf("OCSF %s:%s [%s] %s %s", class, activity, sev, action, details)
	if ctx != "" {
		msg += " " + ctx
	}
	return ev.TS + " " + strings.TrimSpace(msg)
}

func ocsfClassActivity(ev auditEvent) (class, activity string) {
	switch ev.Action {
	case "reload":
		return "CONFIG", "LOADED"
	case "finding":
		return "FINDING", "CREATE"
	case "lifecycle":
		return "LIFECYCLE", "START"
	case "proc":
		return "PROC", "LAUNCH"
	case "proc_exit":
		return "PROC", "EXIT"
	case "reject":
		if ev.Method != "" {
			return "HTTP", strings.ToUpper(ev.Method)
		}
		return "NET", "OPEN"
	}
	if ev.Method != "" {
		m := strings.ToUpper(ev.Method)
		if m == "" {
			m = "OTHER"
		}
		return "HTTP", m
	}
	switch ev.Action {
	case "error", "dial_error":
		return "NET", "OPEN"
	default:
		return "NET", "OPEN"
	}
}

func ocsfSeverity(ev auditEvent) string {
	switch ev.Action {
	case "deny", "reject", "finding":
		return "MED"
	case "error":
		return "HIGH"
	case "dial_error":
		return "LOW"
	case "audit":
		return "INFO"
	case "reload", "lifecycle", "proc", "proc_exit":
		return "INFO"
	default:
		if ev.Allow {
			return "INFO"
		}
		return "MED"
	}
}

func ocsfAction(ev auditEvent) string {
	switch ev.Action {
	case "deny", "reject":
		return "DENIED"
	case "allow", "audit":
		return "ALLOWED"
	case "reload":
		return "LOADED"
	case "finding":
		return "DENIED"
	case "proc", "proc_exit", "lifecycle":
		return "ALLOWED"
	case "error", "dial_error":
		if ev.Allow {
			return "FAILED"
		}
		return "DENIED"
	default:
		if ev.Allow {
			return "ALLOWED"
		}
		return "DENIED"
	}
}

func ocsfDetails(ev auditEvent) string {
	bin := strings.TrimSpace(ev.Binary)
	if bin == "" {
		bin = "-"
	}
	switch {
	case ev.Action == "reload":
		if ev.Reason != "" {
			return ev.Reason
		}
		return "policy reloaded"
	case ev.Method != "" && ev.Path != "":
		scheme := "http"
		if ev.Port == 443 {
			scheme = "https"
		}
		hostport := ev.Host
		if ev.Port > 0 && ev.Port != 80 && ev.Port != 443 {
			hostport = fmt.Sprintf("%s:%d", ev.Host, ev.Port)
		}
		return fmt.Sprintf("%s %s://%s%s", strings.ToUpper(ev.Method), scheme, hostport, ev.Path)
	case ev.Host != "":
		dest := ev.Host
		if ev.Port > 0 {
			dest = fmt.Sprintf("%s:%d", ev.Host, ev.Port)
		}
		return fmt.Sprintf("%s -> %s", bin, dest)
	default:
		if ev.Reason != "" {
			return ev.Reason
		}
		return "-"
	}
}

func ocsfContext(ev auditEvent) string {
	var parts []string
	if ev.Reason != "" && ev.Action != "reload" {
		// Avoid duplicating reason when it is already the sole detail.
		if ev.Host != "" || ev.Method != "" {
			parts = append(parts, "reason:"+ev.Reason)
		}
	}
	if ev.Action == "audit" {
		parts = append(parts, "enforcement:audit")
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, " ") + "]"
}
