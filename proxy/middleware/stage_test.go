package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemovedJWTConfigFailsClosed(t *testing.T) {
	stage := &rejectedConfigStage{Label: "removed_jwt_env", Reason: "JWT middleware environment configuration was removed; refusing request"}
	decision, err := stage.Evaluate(context.Background(), Request{Headers: map[string]string{"Authorization": "Bearer forged"}})
	if err != nil || decision.Allow || decision.Reason == "" {
		t.Fatalf("decision=%+v err=%v; removed JWT configuration must never authorize", decision, err)
	}
}

func TestRemoteStage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Decision{Allow: false, Reason: "nope"})
	}))
	defer srv.Close()
	p := &Pipeline{Stages: []Stage{
		&remoteStage{URL: srv.URL, FailClosed: true},
	}}
	dec, err := p.Run(context.Background(), Request{Host: "x", Method: "GET", Path: "/"})
	if err != nil || dec.Allow {
		t.Fatalf("dec=%v err=%v", dec, err)
	}
}

func TestRemoteStageOversizedFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxRemoteStageBody+8))
	}))
	defer srv.Close()
	st := &remoteStage{URL: srv.URL, FailClosed: true}
	dec, err := st.Evaluate(context.Background(), Request{Host: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow || dec.Reason != "remote stage response too large" {
		t.Fatalf("dec=%+v", dec)
	}
}

func TestRemoteStageOversizedFailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxRemoteStageBody+8))
	}))
	defer srv.Close()
	st := &remoteStage{URL: srv.URL, FailClosed: false}
	dec, err := st.Evaluate(context.Background(), Request{Host: "x"})
	if err != nil || !dec.Allow {
		t.Fatalf("dec=%+v err=%v", dec, err)
	}
}
