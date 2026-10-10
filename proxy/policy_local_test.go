// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-core/engine"
	"github.com/cautem/cautem-core/policy"
)

func TestServePolicyLocalRoutes(t *testing.T) {
	var eng engine.Allowlist
	doc := policy.Document{
		Version: 1,
		NetworkPolicies: map[string]policy.NetworkPolicy{
			"example": {Name: "example", Endpoints: []policy.AllowRule{{Host: "example.com", Port: 443}}},
		},
	}
	_ = eng.Apply(doc)
	srv := NewServer(&eng, io.Discard)
	_ = srv.Apply(context.Background(), doc)
	srv.recordDenial("ts OCSF NET:OPEN [MED] DENY host=blocked.example")

	// current
	var buf bytes.Buffer
	req, _ := http.NewRequest(http.MethodGet, "https://policy.local/v1/policy/current", nil)
	srv.servePolicyLocalRequest(&buf, req)
	resp, err := http.ReadResponse(bufio.NewReader(&buf), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "example.com") {
		t.Fatalf("current: %d %s", resp.StatusCode, body)
	}

	// denials
	buf.Reset()
	req, _ = http.NewRequest(http.MethodGet, "https://policy.local/v1/denials?last=5", nil)
	srv.servePolicyLocalRequest(&buf, req)
	resp, err = http.ReadResponse(bufio.NewReader(&buf), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var den struct {
		Denials []string `json:"denials"`
	}
	if err := json.Unmarshal(body, &den); err != nil || len(den.Denials) != 1 {
		t.Fatalf("denials: %v %s", err, body)
	}

	// submit
	buf.Reset()
	payload := `{"intent_summary":"need api","operations":[{"addRule":{"ruleName":"api_example","rule":{"endpoints":[{"host":"api.example.com","port":443}]}}}]}`
	req, _ = http.NewRequest(http.MethodPost, "https://policy.local/v1/proposals", strings.NewReader(payload))
	srv.servePolicyLocalRequest(&buf, req)
	resp, err = http.ReadResponse(bufio.NewReader(&buf), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var sub struct {
		Accepted []string `json:"accepted_chunk_ids"`
	}
	if err := json.Unmarshal(body, &sub); err != nil || len(sub.Accepted) != 1 {
		t.Fatalf("submit: %v %s", err, body)
	}
	id := sub.Accepted[0]

	// get pending
	buf.Reset()
	req, _ = http.NewRequest(http.MethodGet, "https://policy.local/v1/proposals/"+id, nil)
	srv.servePolicyLocalRequest(&buf, req)
	resp, err = http.ReadResponse(bufio.NewReader(&buf), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), `"status":"pending"`) {
		t.Fatalf("get pending: %s", body)
	}

	// approve locally + reload policy including host
	srv.mu.Lock()
	p := srv.proposals[id]
	p.Status = "approved"
	p.DecidedAt = time.Now().UTC()
	p.ReloadGenAtDecide = srv.policyGen
	srv.mu.Unlock()
	doc2 := policy.Document{
		Version: 1,
		NetworkPolicies: map[string]policy.NetworkPolicy{
			"example":     {Name: "example", Endpoints: []policy.AllowRule{{Host: "example.com", Port: 443}}},
			"api_example": {Name: "api_example", Endpoints: []policy.AllowRule{{Host: "api.example.com", Port: 443}}},
		},
	}
	_ = srv.Apply(context.Background(), doc2)

	buf.Reset()
	req, _ = http.NewRequest(http.MethodGet, "https://policy.local/v1/proposals/"+id+"/wait?timeout=2", nil)
	srv.servePolicyLocalRequest(&buf, req)
	resp, err = http.ReadResponse(bufio.NewReader(&buf), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st["status"] != "approved" || st["policy_reloaded"] != true {
		t.Fatalf("wait: %s", body)
	}
}

func TestNormalizeAddRuleYAML(t *testing.T) {
	hosts, y, err := normalizeAddRuleYAML("gh", map[string]any{
		"endpoints": []any{
			map[string]any{"host": "api.github.com", "port": 443},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "api.github.com" {
		t.Fatalf("hosts=%v", hosts)
	}
	if !strings.Contains(y, "api.github.com") {
		t.Fatalf("yaml=%s", y)
	}
}

func TestIsPolicyLocal(t *testing.T) {
	s := NewServer(nil, io.Discard)
	if !s.isPolicyLocal("policy.local") || !s.isPolicyLocal("POLICY.LOCAL") {
		t.Fatal("expected match")
	}
	if s.isPolicyLocal("evil.local") {
		t.Fatal("unexpected")
	}
}

func TestDenyBodyJSON(t *testing.T) {
	b := DenyBodyJSON("x.com", 443, "no rule")
	if !bytes.Contains(b, []byte("policy_denied")) || !bytes.Contains(b, []byte("policy.local")) {
		t.Fatalf("%s", b)
	}
}
