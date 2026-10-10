package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cauteum-haven/cauteum-core/engine"
	"github.com/cauteum-haven/cauteum-core/policy"
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
	ctx := t.Context()
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

func TestWatchPolicyReportsAppliedRevision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body := []byte(`# cauteum-policy-revision: 7
version: 1
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	reported := make(chan uint32, 1)
	srv := NewServer(&eng, os.Stderr)
	srv.ReportPolicyStatus = func(_ context.Context, revision uint32, loadError string) error {
		if loadError != "" {
			t.Errorf("unexpected policy load error: %s", loadError)
		}
		reported <- revision
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.WatchPolicy(ctx, path, 10*time.Millisecond)
	select {
	case revision := <-reported:
		if revision != 7 {
			t.Fatalf("reported revision=%d, want 7", revision)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not report applied policy revision")
	}
}

func TestWatchPolicyAcknowledgementFailureFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body := []byte(`# cauteum-policy-revision: 9
version: 1
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&eng, os.Stderr)
	srv.ReportPolicyStatus = func(context.Context, uint32, string) error { return errors.New("gateway unavailable") }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.WatchPolicy(ctx, path, 10*time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		decision, decideErr := eng.Decide(context.Background(), engine.EgressRequest{Host: "api.example.com", Port: 443})
		if decideErr == nil && !decision.Allow {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("policy remained allowed after acknowledgement failure")
}

func TestWatchPolicyFailsClosedOnInvalidFileAndRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	allowed := []byte(`version: 1
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
`)
	if err := os.WriteFile(path, allowed, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Parse(allowed)
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
	go srv.WatchPolicy(ctx, path, 20*time.Millisecond)
	write := func(body []byte) {
		t.Helper()
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	waitDecision := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			decision, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "api.example.com", Port: 443})
			if err == nil && decision.Allow == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("decision allow=%v, want %v", !want, want)
	}
	write([]byte("version: [invalid"))
	waitDecision(false)
	write(allowed)
	waitDecision(true)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitDecision(false)
	write(allowed)
	waitDecision(true)
}
