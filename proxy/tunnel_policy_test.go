package proxy

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/whaleshell/whaleshell-core/engine"
	"github.com/whaleshell/whaleshell-core/policy"
)

func TestPolicyUpdateClosesActiveTunnel(t *testing.T) {
	var eng engine.Allowlist
	srv := NewServerForTests(&eng, io.Discard)
	proxySide, clientSide := net.Pipe()
	defer clientSide.Close()
	release, ok := srv.trackTunnel(proxySide, 0)
	if !ok {
		t.Fatal("initial policy generation should be trackable")
	}
	defer release()
	if err := srv.Apply(context.Background(), policy.Document{Version: 1}); err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	if _, err := clientSide.Write([]byte("after-revoke")); err == nil {
		t.Fatal("active tunnel remained writable after policy update")
	}
	staleProxy, staleClient := net.Pipe()
	defer staleProxy.Close()
	defer staleClient.Close()
	if _, ok := srv.trackTunnel(staleProxy, 0); ok {
		t.Fatal("stale policy generation unexpectedly opened a tunnel")
	}
}
