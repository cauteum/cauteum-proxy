package proxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/whaleshell/whaleshell-core/policy"
)

// WatchPolicy polls path for content changes and calls Apply on the server.
// Interval defaults to 1s. Stops when ctx is done.
func (s *Server) WatchPolicy(ctx context.Context, path string, interval time.Duration) {
	if s == nil || strings.TrimSpace(path) == "" {
		return
	}
	if interval <= 0 {
		interval = time.Second
	}
	var lastHash [32]byte
	failClosed := false
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			raw, err := os.ReadFile(path)
			if err != nil {
				if !failClosed {
					s.failClosedPolicy("policy read: " + err.Error())
					failClosed = true
				}
				continue
			}
			revision := policyRevision(raw)
			hash := sha256.Sum256(raw)
			if hash == lastHash && !failClosed {
				continue
			}
			doc, err := policy.Parse(raw)
			if err != nil {
				s.failClosedPolicy("policy reload: " + err.Error())
				_ = s.reportPolicyStatus(ctx, revision, err)
				lastHash = hash
				failClosed = true
				continue
			}
			if err := s.Apply(ctx, doc); err != nil {
				s.failClosedPolicy("policy apply: " + err.Error())
				_ = s.reportPolicyStatus(ctx, revision, err)
				lastHash = hash
				failClosed = true
				continue
			}
			lastHash = hash
			failClosed = false
			if err := s.reportPolicyStatus(ctx, revision, nil); err != nil {
				lastHash = hash
				failClosed = true
				continue
			}
			s.logAudit(auditEvent{Action: "reload", Reason: fmt.Sprintf("policy reloaded from %s", path), Allow: true})
		}
	}
}

func (s *Server) reportPolicyStatus(ctx context.Context, revision uint32, loadErr error) error {
	if s == nil || s.ReportPolicyStatus == nil || revision == 0 {
		return nil
	}
	message := ""
	if loadErr != nil {
		message = loadErr.Error()
	}
	err := s.ReportPolicyStatus(ctx, revision, message)
	if err != nil && loadErr == nil {
		// A locally applied allowlist without a gateway acknowledgement leaves
		// the control plane unable to prove which revision is active.
		s.failClosedPolicy("policy acknowledgement: " + err.Error())
	}
	return err
}

func policyRevision(raw []byte) uint32 {
	const prefix = "# whaleshell-policy-revision:"
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, prefix)), 10, 32)
		if err == nil {
			return uint32(value)
		}
	}
	return 0
}

// failClosedPolicy replaces a possibly stale allowlist with an empty, valid
// default-deny policy. Apply also closes tunnels admitted by the old revision.
func (s *Server) failClosedPolicy(reason string) {
	if err := s.Apply(context.Background(), policy.Document{Version: 1}); err != nil {
		s.logAudit(auditEvent{Action: "error", Reason: reason + "; deny-all apply failed: " + err.Error(), Allow: false})
		return
	}
	s.logAudit(auditEvent{Action: "error", Reason: reason + "; active policy cleared (default deny)", Allow: false})
}
