package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/whaleshell/whaleshell-core/engine"
	"github.com/whaleshell/whaleshell-core/policy"
)

func TestWatchPolicyReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body1 := []byte(`version: 1
network_policies:
  a:
    name: a
    endpoints:
      - host: a.example.com
        port: 443
`)
	if err := os.WriteFile(path, body1, 0o644); err != nil {
		t.Fatal(err)
	}
	initialInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&eng, os.Stderr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.WatchPolicy(ctx, path, 50*time.Millisecond)

	body2 := []byte(`version: 1
network_policies:
  b:
    name: b
    endpoints:
      - host: b.example.com
        port: 443
`)
	time.Sleep(80 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(body2); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if len(body1) != len(body2) {
		t.Fatal("test requires equal-length policies")
	}
	if err := os.Chtimes(path, initialInfo.ModTime(), initialInfo.ModTime()); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		dec, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "b.example.com", Port: 443})
		if err == nil && dec.Allow {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("policy did not reload to allow b.example.com")
}
