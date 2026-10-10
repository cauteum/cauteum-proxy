package proxy_test

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cautem/cautem-core/env"
	"github.com/cautem/cautem-proxy/proxy"
)

func TestRewriteHeaderQueryPathBasic(t *testing.T) {
	secrets := proxy.SecretStore{
		"API_KEY": "secret-value",
		"PASS":    "p@ss",
	}
	req, _ := http.NewRequest(http.MethodGet, "http://api.example/bot"+env.PlaceholderPrefix+"API_KEY/x?token="+env.PlaceholderPrefix+"API_KEY", nil)
	req.Header.Set("Authorization", "Bearer "+env.PlaceholderPrefix+"API_KEY")
	basic := base64.StdEncoding.EncodeToString([]byte("user:" + env.PlaceholderPrefix + "PASS"))
	req.Header.Set("X-Basic", "Basic "+basic)

	if err := proxy.RewriteHTTPRequest(req, secrets); err != nil {
		t.Fatal(err)
	}
	if req.URL.Path != "/botsecret-value/x" && req.URL.Path != "botsecret-value/x" {
		// Path may keep leading slash from URL parser
		if req.URL.Path != "/botsecret-value/x" {
			t.Fatalf("path=%q", req.URL.Path)
		}
	}
	if req.URL.Query().Get("token") != "secret-value" {
		t.Fatalf("query=%q", req.URL.RawQuery)
	}
	if req.Header.Get("Authorization") != "Bearer secret-value" {
		t.Fatalf("auth=%q", req.Header.Get("Authorization"))
	}
	decoded, _ := base64.StdEncoding.DecodeString(stringsTrimBasic(req.Header.Get("X-Basic")))
	if string(decoded) != "user:p@ss" {
		t.Fatalf("basic=%q", decoded)
	}
}

func TestRewriteFailClosed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("X-Key", env.PlaceholderPrefix+"MISSING")
	err := proxy.RewriteHTTPRequest(req, proxy.SecretStore{})
	if err == nil {
		t.Fatal("expected unresolved error")
	}
}

func TestRewriteRequestBodyOptIn(t *testing.T) {
	body := `{"token":"` + env.PlaceholderPrefix + `API_KEY"}`
	req, _ := http.NewRequest(http.MethodPost, "http://api.example/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := proxy.RewriteHTTPRequest(req, proxy.SecretStore{"API_KEY": "secret"}); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != body {
		t.Fatalf("default rewrite changed body: %s", got)
	}

	req, _ = http.NewRequest(http.MethodPost, "http://api.example/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := proxy.RewriteHTTPRequestWithOptions(req, proxy.SecretStore{"API_KEY": "secret"}, true); err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(req.Body)
	if string(got) != `{"token":"secret"}` {
		t.Fatalf("rewritten body=%s", got)
	}
	if req.ContentLength != int64(len(got)) || req.Header.Get("Content-Length") != "18" {
		t.Fatalf("content length not updated: length=%d header=%q", req.ContentLength, req.Header.Get("Content-Length"))
	}
}

func TestRewriteFormBodyCredentialValues(t *testing.T) {
	body := "access_token=" + env.PlaceholderPrefix + "API_KEY"
	req, _ := http.NewRequest(http.MethodPost, "http://api.example/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := proxy.RewriteHTTPRequestWithOptions(req, proxy.SecretStore{"API_KEY": "secret value"}, true); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != "access_token=secret+value" {
		t.Fatalf("rewritten form=%q", got)
	}
}

func TestRewriteUnsupportedBodyContentTypeFailsOnPlaceholder(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://api.example/", strings.NewReader(env.PlaceholderPrefix+"API_KEY"))
	req.Header.Set("Content-Type", "application/vnd.example+json")
	if err := proxy.RewriteHTTPRequestWithOptions(req, proxy.SecretStore{"API_KEY": "secret"}, true); err == nil {
		t.Fatal("expected unsupported content type failure")
	}
}

func TestRewriteLegacyPlaceholderAlias(t *testing.T) {
	legacy := "openshell:resolve:env:API_KEY"
	secrets := proxy.SecretStore{"API_KEY": "secret-value"}
	req, _ := http.NewRequest(http.MethodGet, "http://api.example/", nil)
	req.Header.Set("Authorization", "Bearer "+legacy)
	if err := proxy.RewriteHTTPRequest(req, secrets); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer secret-value" {
		t.Fatalf("auth=%q", req.Header.Get("Authorization"))
	}
}

func TestRewritePreservesEncodedSlashInPath(t *testing.T) {
	for _, test := range []struct{ target, want string }{
		{target: "http://api.example/repos/group%2Fproject", want: "/repos/group%2Fproject"},
		{target: "http://api.example/repos/group%2fproject", want: "/repos/group%2fproject"},
	} {
		req, err := http.NewRequest(http.MethodGet, test.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := proxy.RewriteHTTPRequest(req, proxy.SecretStore{}); err != nil {
			t.Fatal(err)
		}
		if got := req.URL.EscapedPath(); got != test.want {
			t.Fatalf("escaped path=%q, want %q", got, test.want)
		}
	}
}

func TestRewriteCredentialPathPreservesEncodedSlash(t *testing.T) {
	target := "http://api.example/repos/" + env.PlaceholderPrefix + "ORG%2Fproject"
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.RewriteHTTPRequest(req, proxy.SecretStore{"ORG": "group"}); err != nil {
		t.Fatal(err)
	}
	if got := req.URL.EscapedPath(); got != "/repos/group%2Fproject" {
		t.Fatalf("escaped path=%q", got)
	}
}

func TestCredentialEndpointMismatch(t *testing.T) {
	secrets := proxy.SecretStore{
		"GITHUB_TOKEN":   "gh-secret",
		"OPENAI_API_KEY": "oai-secret",
	}
	req, _ := http.NewRequest(http.MethodGet, "http://api.openai.com/v1", nil)
	req.Header.Set("Authorization", "Bearer "+env.PlaceholderPrefix+"GITHUB_TOKEN")
	used := proxy.PlaceholderKeysInRequest(req)
	if len(used) != 1 || used[0] != "GITHUB_TOKEN" {
		t.Fatalf("used=%v", used)
	}
	// OpenAI endpoint only binds OPENAI_API_KEY
	_, err := proxy.SecretsForEndpoint(secrets, []string{"OPENAI_API_KEY"}, used)
	if err == nil || !errors.Is(err, proxy.ErrCredentialEndpointMismatch) {
		t.Fatalf("err=%v", err)
	}
	// GitHub-bound endpoint allows GITHUB_TOKEN
	rew, err := proxy.SecretsForEndpoint(secrets, []string{"GITHUB_TOKEN", "GH_TOKEN"}, used)
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.RewriteHTTPRequest(req, rew); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer gh-secret" {
		t.Fatalf("auth=%q", req.Header.Get("Authorization"))
	}
	// Empty binding rejects any placeholder
	_, err = proxy.SecretsForEndpoint(secrets, nil, used)
	if err == nil {
		t.Fatal("expected mismatch on empty binding")
	}
}

func TestCredentialKeysSurviveYAML(t *testing.T) {
	// covered in cautem-core; smoke here via FilterSecrets empty semantics
	if len(proxy.FilterSecrets(proxy.SecretStore{"A": "1"}, nil)) != 0 {
		t.Fatal("empty bound keys must yield empty store")
	}
}

func stringsTrimBasic(v string) string {
	const p = "Basic "
	if len(v) > len(p) {
		return v[len(p):]
	}
	return v
}

func TestLoadSecretsFromEnvironSkipsControlPlaneTokens(t *testing.T) {
	store := proxy.LoadSecretsFromEnviron([]string{
		"OPENAI_API_KEY=sk-real",
		"CAUTEM_SANDBOX_TOKEN=supervisor-secret",
		"CAUTEM_GATEWAY_TOKEN=operator-secret",
	})
	if store["OPENAI_API_KEY"] != "sk-real" {
		t.Fatalf("credential missing: %v", store)
	}
	for _, k := range []string{"CAUTEM_SANDBOX_TOKEN", "CAUTEM_GATEWAY_TOKEN"} {
		if _, ok := store[k]; ok {
			t.Fatalf("%s must never be resolvable by sandbox placeholders", k)
		}
	}
}
