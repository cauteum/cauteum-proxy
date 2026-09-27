package proxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
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
	if raw, err := os.ReadFile(path); err == nil {
		lastHash = sha256.Sum256(raw)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			hash := sha256.Sum256(raw)
			if hash == lastHash {
				continue
			}
			doc, err := policy.Parse(raw)
			if err != nil {
				s.logAudit(auditEvent{Action: "error", Reason: "policy reload: " + err.Error(), Allow: false})
				continue
			}
			if err := s.Apply(ctx, doc); err != nil {
				s.logAudit(auditEvent{Action: "error", Reason: "policy apply: " + err.Error(), Allow: false})
				continue
			}
			lastHash = hash
			s.logAudit(auditEvent{Action: "reload", Reason: fmt.Sprintf("policy reloaded from %s", path), Allow: true})
		}
	}
}
