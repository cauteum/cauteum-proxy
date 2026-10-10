package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/cauteum/cauteum-core/engine"
	"github.com/cauteum/cauteum-core/policy"
)

func TestOpenShellQuerySelectorsDecideEveryRepeatedValue(t *testing.T) {
	doc, err := policy.Parse([]byte(`version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        rules:
          - allow:
              method: GET
              path: /repos
              query:
                repo: {any: ["NVIDIA/*", "openai/*"]}
        deny_rules:
          - method: GET
            path: /repos
            query:
              repo: "*/private*"
`))
	if err != nil {
		t.Fatal(err)
	}
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	for _, tc := range []struct {
		query string
		allow bool
	}{
		{"repo=NVIDIA%2Frepo%2Ffile", true},
		{"repo=NVIDIA/public&repo=openai/public", true},
		{"repo=NVIDIA/public&repo=other/public", false},
		{"repo=NVIDIA/public&repo=openai/private-key", false},
		{"other=NVIDIA/public", false},
		{"repo=NVIDIA/a;b", true},
		{"repo=NVIDIA/a+b", true},
		{"repo=NVIDIA/%FF", false},
		{"repo=NVIDIA/%QQ", false},
	} {
		req := httptest.NewRequest("GET", "https://api.example.com/repos?"+tc.query, nil)
		req.RequestURI = "/repos?" + tc.query
		decision, err := server.decideHTTP(req, eng, "api.example.com", 443, "/repos", "")
		if err != nil || decision.Allow != tc.allow {
			t.Fatalf("query=%q allow=%v want=%v reason=%s err=%v", tc.query, decision.Allow, tc.allow, decision.Reason, err)
		}
	}
}

func TestOpenShellQueryDecoding(t *testing.T) {
	query, err := parsePolicyQuery("&&x=a+b&x=a%2Bb&empty&=value&semi=a;b")
	if err != nil {
		t.Fatal(err)
	}
	if len(query["x"]) != 2 || query["x"][0] != "a b" || query["x"][1] != "a+b" || query["empty"][0] != "" || query[""][0] != "value" || query["semi"][0] != "a;b" {
		t.Fatalf("decoded=%v", query)
	}
}
