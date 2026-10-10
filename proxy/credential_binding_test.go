package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cautem/cautem-core/engine"
	"github.com/cautem/cautem-core/policy"
)

func TestUninspectedCredentialPolicy(t *testing.T) {
	for _, test := range []struct {
		name      string
		allow     bool
		wantBlock bool
	}{
		{name: "credentialed L4 blocks", wantBlock: true},
		{name: "explicit opt-in allows", allow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := policy.AllowRule{
				Host: "db.example.com", Port: 5432,
				CredentialKeys: []string{"DB_TOKEN"}, AllowUninspectedCredentials: test.allow,
			}
			if got := blocksUninspectedCredentials(rule); got != test.wantBlock {
				t.Fatalf("blocks=%v, want %v", got, test.wantBlock)
			}

			var eng engine.Allowlist
			if err := eng.Apply(policy.Document{Version: 1, NetworkPolicies: map[string]policy.NetworkPolicy{
				"db": {Endpoints: []policy.AllowRule{rule}},
			}}); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "http://db.example.com/query", nil)
			decision, err := NewServer(&eng, nil).decideHTTP(req, &eng, "db.example.com", 5432, "/query", "")
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allow == test.wantBlock {
				t.Fatalf("decision=%+v, wantBlock=%v", decision, test.wantBlock)
			}
		})
	}
}

func TestHandleCONNECTBlocksUninspectedBoundCredentials(t *testing.T) {
	rule := policy.AllowRule{
		Host: "db.example.com", Port: 5432,
		CredentialKeys: []string{"DB_TOKEN"},
	}
	var eng engine.Allowlist
	if err := eng.Apply(policy.Document{Version: 1, NetworkPolicies: map[string]policy.NetworkPolicy{
		"db": {Endpoints: []policy.AllowRule{rule}},
	}}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("CONNECT", "http://db.example.com:5432", nil)
	req.Host = "db.example.com:5432"
	response := httptest.NewRecorder()
	NewServer(&eng, nil).handleCONNECT(response, req)
	if response.Code != 403 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "requires L7 inspection") {
		t.Fatalf("body=%s", response.Body.String())
	}
}
