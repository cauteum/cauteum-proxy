package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/cauteum/cauteum-core/engine"
	"github.com/cauteum/cauteum-core/policy"
)

func TestCanonicalizeL7Path(t *testing.T) {
	tests := []struct {
		path       string
		allowSlash bool
		want       string
		wantError  bool
	}{
		{path: "/repos/group%2fproject", wantError: true},
		{path: "/repos/group%2fproject", allowSlash: true, want: "/repos/group%2Fproject"},
		{path: "/a/%2e%2e/b", want: "/b"},
		{path: "/a//b/./c", want: "/a/b/c"},
		{path: "/a/..", want: "/"},
		{path: "/public/..%2fsecret", allowSlash: true, wantError: true},
		{path: "/a/../../secret", wantError: true},
		{path: "/repo;version=1/issues", want: "/repo/issues"},
		{path: "/bad%2", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := canonicalizeL7Path(tt.path, tt.allowSlash)
			if (err != nil) != tt.wantError {
				t.Fatalf("canonicalize error=%v, wantError=%v", err, tt.wantError)
			}
			if err == nil && got != tt.want {
				t.Fatalf("canonical=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequestTargetPathUsesOriginalRequestTarget(t *testing.T) {
	req := httptest.NewRequest("GET", "http://api.example.com/parsed", nil)
	req.RequestURI = "http://api.example.com/repos/group%2fproject?ref=feature"
	if got := requestTargetPath(req, "/fallback"); got != "/repos/group%2fproject" {
		t.Fatalf("absolute-form path=%q", got)
	}
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.RequestURI = "/repos/group%2fproject?ref=feature"
	if got := requestTargetPath(req, "/fallback"); got != "/repos/group%2fproject" {
		t.Fatalf("origin-form path=%q", got)
	}
}

func TestDecideHTTPScopesEncodedSlashToMatchedEndpoint(t *testing.T) {
	for _, test := range []struct {
		name       string
		allowSlash bool
		fragment   bool
		wantAllow  bool
	}{
		{name: "strict endpoint rejects", wantAllow: false},
		{name: "opted endpoint allows", allowSlash: true, wantAllow: true},
		{name: "fragment rejected", allowSlash: true, fragment: true, wantAllow: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := policy.AllowRule{
				Host: "api.example.com", Port: 443, TLS: "terminate", Protocol: "rest",
				AllowEncodedSlash: test.allowSlash,
				Rules:             []policy.L7Rule{{Allow: &policy.L7Allow{Method: "GET", Path: "/repos/group%2Fproject"}}},
			}
			var eng engine.Allowlist
			if err := eng.Apply(policy.Document{Version: 1, NetworkPolicies: map[string]policy.NetworkPolicy{
				"api": {Endpoints: []policy.AllowRule{rule}},
			}}); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "https://api.example.com/repos/group%2fproject", nil)
			if test.fragment {
				req.RequestURI += "#fragment"
			}
			server := NewServer(&eng, nil)
			decision, err := server.decideHTTP(req, &eng, "api.example.com", 443, req.URL.EscapedPath(), "")
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allow != test.wantAllow {
				t.Fatalf("decision=%+v, want allow=%v", decision, test.wantAllow)
			}
			if test.wantAllow && req.URL.EscapedPath() != "/repos/group%2Fproject" {
				t.Fatalf("forwarded path=%q", req.URL.EscapedPath())
			}
		})
	}
}
