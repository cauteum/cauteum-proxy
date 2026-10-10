package proxy

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/cauteum/cauteum-core/defaults"
)

type ctxKeyConn struct{}

// withConn stores the underlying net.Conn on the request context (set via Server.ConnContext).
func withConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, ctxKeyConn{}, c)
}

func connFromContext(ctx context.Context) net.Conn {
	c, _ := ctx.Value(ctxKeyConn{}).(net.Conn)
	return c
}

// callerBinary resolves the egress client binary path for policy matching.
// Order: trusted HeaderBinary (tests/ops), then Linux SO_PEERCRED to /proc/<pid>/exe.
func callerBinary(r *http.Request) string {
	if r == nil {
		return ""
	}
	if trustBinaryHeader() {
		if h := strings.TrimSpace(r.Header.Get(defaults.HeaderBinary)); h != "" {
			return h
		}
	}
	if c := connFromContext(r.Context()); c != nil {
		if bin := peerExecutable(c); bin != "" {
			return bin
		}
	}
	return ""
}

func trustBinaryHeader() bool {
	v := strings.TrimSpace(os.Getenv(defaults.EnvTrustBinaryHeader))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
