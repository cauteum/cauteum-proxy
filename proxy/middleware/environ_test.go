package middleware_test

import (
	"context"
	"testing"

	"github.com/cautem/cauteum-proxy/proxy/middleware"
)

func TestFromEnviron(t *testing.T) {
	if p := middleware.FromEnviron([]string{}); p != nil {
		t.Fatal("expected nil")
	}
	p := middleware.FromEnviron([]string{
		"CAUTEUM_MIDDLEWARE_JWT_AUD=cauteum",
		"CAUTEUM_MIDDLEWARE_REMOTE_URL=http://127.0.0.1:9/mw",
	})
	if p == nil || len(p.Stages) != 2 {
		t.Fatalf("stages=%v", p)
	}
	decision, err := p.Run(context.Background(), middleware.Request{})
	if err != nil || decision.Allow || decision.Reason != "JWT middleware environment configuration was removed; refusing request" {
		t.Fatalf("decision=%+v err=%v; configured removed JWT stage must fail closed", decision, err)
	}
	if p := middleware.FromEnviron([]string{"CAUTEUM_MIDDLEWARE_JWT_REQUIRED=false"}); p != nil {
		t.Fatal("explicit false must not activate a removed JWT stage")
	}
}
