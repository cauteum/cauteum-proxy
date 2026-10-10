// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cautem/cautem-core/policy"
	"gopkg.in/yaml.v3"
)

// PolicyLocalHost is the sandbox-local policy advisor hostname (OpenShell-compatible).
const PolicyLocalHost = "policy.local"

const (
	policyLocalMaxBody       = 64 << 10
	policyLocalDenialsMax    = 100
	policyLocalWaitDefault   = 60
	policyLocalWaitMin       = 1
	policyLocalWaitMax       = 300
	policyLocalAgentGuidance = "cautem blocked this request with sandbox policy. If the user task still needs this network action, read /etc/cautem/skills/policy_advisor.md, submit the narrowest proposal to http://policy.local/v1/proposals, wait for approval with policy_reloaded: true, then retry."
)

type denialLine struct {
	TS   time.Time
	Text string
}

type localProposal struct {
	ID                string          `json:"id"`
	Sandbox           string          `json:"sandbox,omitempty"`
	Status            string          `json:"status"` // pending|approved|rejected
	IntentSummary     string          `json:"intent_summary,omitempty"`
	RuleName          string          `json:"rule_name,omitempty"`
	RuleYAML          string          `json:"rule_yaml,omitempty"`
	Hosts             []string        `json:"hosts,omitempty"`
	RejectionReason   string          `json:"rejection_reason,omitempty"`
	ValidationResult  string          `json:"validation_result,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	DecidedAt         time.Time       `json:"decided_at"`
	RawOps            json.RawMessage `json:"-"`
	ReloadGenAtDecide int             `json:"-"`
}

func (s *Server) isPolicyLocal(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == PolicyLocalHost || h == "policy.cautem.local"
}

func (s *Server) recordDenial(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denials = append(s.denials, denialLine{TS: time.Now().UTC(), Text: line})
	if len(s.denials) > policyLocalDenialsMax {
		s.denials = s.denials[len(s.denials)-policyLocalDenialsMax:]
	}
}

func (s *Server) handlePolicyLocal(_ http.ResponseWriter, _ *http.Request, client net.Conn) {
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	tlsConn, err := s.mitmHandshake(client, PolicyLocalHost)
	if err != nil {
		s.logAudit(auditEvent{Action: "error", Host: PolicyLocalHost, Reason: err.Error(), Allow: false})
		return
	}
	defer tlsConn.Close()

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		s.servePolicyLocalRequest(tlsConn, req)
	}
}

func (s *Server) servePolicyLocalRequest(w io.Writer, req *http.Request) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(req.Body, policyLocalMaxBody))
		_ = req.Body.Close()
	}
	path := req.URL.Path
	switch {
	case req.Method == http.MethodGet && path == "/v1/policy/current":
		s.policyLocalCurrent(w)
	case req.Method == http.MethodGet && path == "/v1/denials":
		s.policyLocalDenials(w, req)
	case req.Method == http.MethodPost && path == "/v1/proposals":
		s.policyLocalSubmit(w, body)
	case req.Method == http.MethodGet && strings.HasPrefix(path, "/v1/proposals/"):
		rest := strings.TrimPrefix(path, "/v1/proposals/")
		id, wait := rest, false
		if strings.HasSuffix(rest, "/wait") {
			wait = true
			id = strings.TrimSuffix(rest, "/wait")
			id = strings.TrimSuffix(id, "/")
		}
		if wait {
			s.policyLocalWait(w, req, id)
		} else {
			s.policyLocalGet(w, id)
		}
	default:
		writePolicyLocalJSON(w, http.StatusNotFound, map[string]any{"error": "not_found", "path": path})
	}
}

func (s *Server) policyLocalCurrent(w io.Writer) {
	doc := s.CurrentDocument()
	b, err := yaml.Marshal(doc)
	if err != nil {
		writePolicyLocalJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 200 OK\r\nContent-Type: application/yaml\r\nContent-Length: %d\r\n\r\n", len(b))
	buf.Write(b)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) policyLocalDenials(w io.Writer, req *http.Request) {
	last := 10
	if v := req.URL.Query().Get("last"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			last = n
		}
	}
	if last > policyLocalDenialsMax {
		last = policyLocalDenialsMax
	}
	s.mu.RLock()
	den := append([]denialLine{}, s.denials...)
	s.mu.RUnlock()
	if last < len(den) {
		den = den[len(den)-last:]
	}
	lines := make([]string, 0, len(den))
	for _, d := range slices.Backward(den) {
		lines = append(lines, d.Text)
	}
	writePolicyLocalJSON(w, http.StatusOK, map[string]any{"denials": lines})
}

type proposalSubmitBody struct {
	IntentSummary string           `json:"intent_summary"`
	Operations    []map[string]any `json:"operations"`
}

func (s *Server) policyLocalSubmit(w io.Writer, body []byte) {
	var req proposalSubmitBody
	if err := json.Unmarshal(body, &req); err != nil {
		writePolicyLocalJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json: " + err.Error()})
		return
	}
	if len(req.Operations) == 0 {
		writePolicyLocalJSON(w, http.StatusBadRequest, map[string]any{"error": "proposal requires at least one operation"})
		return
	}

	var accepted []string
	var rejected []map[string]string
	for _, op := range req.Operations {
		raw, ok := op["addRule"]
		if !ok {
			rejected = append(rejected, map[string]string{"error": "only addRule operations are supported"})
			continue
		}
		p, err := proposalFromAddRule(raw, req.IntentSummary)
		if err != nil {
			rejected = append(rejected, map[string]string{"error": err.Error()})
			continue
		}
		p.Sandbox = strings.TrimSpace(os.Getenv("CAUTEM_SANDBOX"))
		if err := s.persistProposal(p); err != nil {
			rejected = append(rejected, map[string]string{"error": err.Error()})
			continue
		}
		accepted = append(accepted, p.ID)
	}
	status := http.StatusAccepted
	if len(accepted) == 0 {
		status = http.StatusBadRequest
	}
	writePolicyLocalJSON(w, status, map[string]any{
		"accepted_chunk_ids": accepted,
		"rejection_reasons":  rejected,
	})
}

func proposalFromAddRule(raw any, intent string) (*localProposal, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var add struct {
		RuleName string         `json:"ruleName"`
		Rule     map[string]any `json:"rule"`
	}
	if err := json.Unmarshal(b, &add); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(add.RuleName)
	if name == "" {
		if n, _ := add.Rule["name"].(string); strings.TrimSpace(n) != "" {
			name = strings.TrimSpace(n)
		}
	}
	if name == "" {
		return nil, fmt.Errorf("addRule.ruleName or rule.name is required")
	}
	hosts, ruleYAML, err := normalizeAddRuleYAML(name, add.Rule)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if strings.EqualFold(h, "metadata.google.internal") || strings.HasPrefix(h, "169.254.") {
			return nil, fmt.Errorf("refusing SSRF-sensitive host %q", h)
		}
	}
	id, err := newChunkID()
	if err != nil {
		return nil, err
	}
	return &localProposal{
		ID:               id,
		Status:           "pending",
		IntentSummary:    intent,
		RuleName:         name,
		RuleYAML:         ruleYAML,
		Hosts:            hosts,
		CreatedAt:        time.Now().UTC(),
		ValidationResult: "ok: narrow addRule accepted for human review",
	}, nil
}

func normalizeAddRuleYAML(name string, rule map[string]any) (hosts []string, yamlOut string, err error) {
	// Accept OpenShell-ish {endpoints:[...]} or already-flat endpoint fields.
	var endpoints []policy.AllowRule
	if rawEps, ok := rule["endpoints"].([]any); ok && len(rawEps) > 0 {
		for _, ep := range rawEps {
			eb, _ := json.Marshal(ep)
			var ar policy.AllowRule
			if err := json.Unmarshal(eb, &ar); err != nil {
				return nil, "", fmt.Errorf("endpoint: %w", err)
			}
			if ar.Host == "" {
				return nil, "", fmt.Errorf("endpoint host required")
			}
			if ar.Port == 0 && len(ar.Ports) == 0 {
				ar.Port = 443
			}
			endpoints = append(endpoints, ar)
			hosts = append(hosts, ar.Host)
		}
	} else {
		eb, _ := json.Marshal(rule)
		var ar policy.AllowRule
		if err := json.Unmarshal(eb, &ar); err != nil {
			return nil, "", err
		}
		if ar.Host == "" {
			return nil, "", fmt.Errorf("rule.host required")
		}
		if ar.Port == 0 && len(ar.Ports) == 0 {
			ar.Port = 443
		}
		endpoints = append(endpoints, ar)
		hosts = append(hosts, ar.Host)
	}
	np := policy.NetworkPolicy{Name: name, Endpoints: endpoints}
	doc := policy.Document{
		Version: 1,
		NetworkPolicies: map[string]policy.NetworkPolicy{
			name: np,
		},
	}
	if err := doc.Validate(); err != nil {
		return nil, "", err
	}
	b, err := yaml.Marshal(map[string]any{
		"network_policies": doc.NetworkPolicies,
	})
	if err != nil {
		return nil, "", err
	}
	return hosts, string(b), nil
}

func (s *Server) persistProposal(p *localProposal) error {
	s.mu.Lock()
	if s.proposals == nil {
		s.proposals = map[string]*localProposal{}
	}
	s.proposals[p.ID] = p
	s.mu.Unlock()

	gw := strings.TrimSpace(os.Getenv("CAUTEM_GATEWAY_URL"))
	sb := strings.TrimSpace(os.Getenv("CAUTEM_SANDBOX"))
	if gw == "" || sb == "" {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{
		"id":                p.ID,
		"intent_summary":    p.IntentSummary,
		"rule_name":         p.RuleName,
		"rule_yaml":         p.RuleYAML,
		"hosts":             p.Hosts,
		"validation_result": p.ValidationResult,
		"status":            p.Status,
	})
	ctx, cancel := context.WithTimeout(context.Background(), proposalRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(gw, "/")+"/v1/sandboxes/"+sb+"/proposals", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	s.gatewayAuth(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		// Keep local pending; host can still sync later.
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("gateway proposals: %s: %s", res.Status, bytes.TrimSpace(b))
	}
	return nil
}

func (s *Server) policyLocalGet(w io.Writer, id string) {
	p := s.lookupProposal(id)
	if p == nil {
		writePolicyLocalJSON(w, http.StatusNotFound, map[string]any{"error": "not_found", "id": id})
		return
	}
	writePolicyLocalJSON(w, http.StatusOK, proposalStatusJSON(p, s.policyReloaded(p)))
}

func (s *Server) policyLocalWait(w io.Writer, req *http.Request, id string) {
	timeout := policyLocalWaitDefault
	if v := req.URL.Query().Get("timeout"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			timeout = n
		}
	}
	if timeout < policyLocalWaitMin {
		timeout = policyLocalWaitMin
	}
	if timeout > policyLocalWaitMax {
		timeout = policyLocalWaitMax
	}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		p := s.lookupProposal(id)
		if p == nil {
			// Refresh from gateway once.
			s.refreshProposalFromGateway(id)
			p = s.lookupProposal(id)
		} else if p.Status == "pending" {
			s.refreshProposalFromGateway(id)
			p = s.lookupProposal(id)
		}
		if p == nil {
			writePolicyLocalJSON(w, http.StatusNotFound, map[string]any{"error": "not_found", "id": id})
			return
		}
		if p.Status == "approved" || p.Status == "rejected" {
			reloaded := s.policyReloaded(p)
			if p.Status == "approved" && !reloaded && time.Now().Before(deadline) {
				time.Sleep(policyPollInterval)
				continue
			}
			out := proposalStatusJSON(p, reloaded)
			writePolicyLocalJSON(w, http.StatusOK, out)
			return
		}
		if time.Now().After(deadline) {
			out := proposalStatusJSON(p, false)
			out["timed_out"] = true
			writePolicyLocalJSON(w, http.StatusOK, out)
			return
		}
		time.Sleep(time.Second)
	}
}

func proposalStatusJSON(p *localProposal, reloaded bool) map[string]any {
	out := map[string]any{
		"id":                p.ID,
		"status":            p.Status,
		"rule_name":         p.RuleName,
		"intent_summary":    p.IntentSummary,
		"validation_result": p.ValidationResult,
		"rejection_reason":  p.RejectionReason,
	}
	if p.Status == "approved" {
		out["policy_reloaded"] = reloaded
	}
	return out
}

func (s *Server) policyReloaded(p *localProposal) bool {
	if p == nil || p.Status != "approved" {
		return false
	}
	doc := s.CurrentDocument()
	for _, h := range p.Hosts {
		for _, r := range doc.AllowRules() {
			if strings.EqualFold(r.Host, h) || r.ID == p.RuleName {
				return true
			}
		}
		if _, ok := doc.NetworkPolicies[p.RuleName]; ok {
			return true
		}
	}
	// Also treat a newer policy generation after decide as reloaded.
	s.mu.RLock()
	gen := s.policyGen
	s.mu.RUnlock()
	return p.ReloadGenAtDecide > 0 && gen > p.ReloadGenAtDecide
}

func (s *Server) lookupProposal(id string) *localProposal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.proposals[id]; ok {
		cp := *p
		return &cp
	}
	return nil
}

func (s *Server) refreshProposalFromGateway(id string) {
	gw := strings.TrimSpace(os.Getenv("CAUTEM_GATEWAY_URL"))
	sb := strings.TrimSpace(os.Getenv("CAUTEM_SANDBOX"))
	if gw == "" || sb == "" || id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), policyRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(gw, "/")+"/v1/sandboxes/"+sb+"/proposals/"+id, nil)
	if err != nil {
		return
	}
	s.gatewayAuth(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return
	}
	var remote localProposal
	if err := json.NewDecoder(res.Body).Decode(&remote); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proposals == nil {
		s.proposals = map[string]*localProposal{}
	}
	cur := s.proposals[id]
	if cur == nil {
		s.proposals[id] = &remote
		return
	}
	if remote.Status != "" {
		cur.Status = remote.Status
	}
	cur.RejectionReason = remote.RejectionReason
	cur.ValidationResult = remote.ValidationResult
	if !remote.DecidedAt.IsZero() {
		cur.DecidedAt = remote.DecidedAt
	}
	if cur.Status == "approved" && cur.ReloadGenAtDecide == 0 {
		cur.ReloadGenAtDecide = s.policyGen
	}
}

func writePolicyLocalJSON(w io.Writer, status int, v any) {
	b, _ := json.Marshal(v)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", status, http.StatusText(status), len(b))
	buf.Write(b)
	_, _ = w.Write(buf.Bytes())
}

func newChunkID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "chk_" + hex.EncodeToString(b[:]), nil
}

// DenyBodyJSON is returned to clients on policy deny (agent-readable).
func DenyBodyJSON(host string, port int, reason string) []byte {
	b, _ := json.Marshal(map[string]any{
		"error":    "policy_denied",
		"host":     host,
		"port":     port,
		"detail":   reason,
		"guidance": policyLocalAgentGuidance,
		"next_steps": []string{
			"GET http://policy.local/v1/policy/current",
			"GET http://policy.local/v1/denials?last=10",
			"POST http://policy.local/v1/proposals",
			"GET http://policy.local/v1/proposals/{chunk_id}/wait?timeout=300",
		},
	})
	return b
}

func (s *Server) gatewayAuth(req *http.Request) {
	if tok := strings.TrimSpace(s.GatewayToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}
