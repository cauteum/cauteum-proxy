package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

type tokenGrantResolverFunc func(context.Context, TokenGrantCredential, TokenGrantTarget) (string, error)

func (f tokenGrantResolverFunc) ResolveTokenGrant(ctx context.Context, g TokenGrantCredential, target TokenGrantTarget) (string, error) {
	return f(ctx, g, target)
}

func TestTokenGrantTLSConfigLoadsGuestMTLSMaterial(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"gateway.test"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath, certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHALESHELL_GUEST_TLS_CA", caPath)
	t.Setenv("WHALESHELL_GUEST_TLS_CERT", certPath)
	t.Setenv("WHALESHELL_GUEST_TLS_KEY", keyPath)
	cfg, err := tokenGrantTLSConfigFromEnvironment("gateway.test")
	if err != nil || cfg.ServerName != "gateway.test" || cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("TLS config=%+v err=%v", cfg, err)
	}
}

func TestResolveTokenGrantPlaceholdersUsesEndpointBoundDynamicCredential(t *testing.T) {
	s := &Server{tokenGrants: map[string]TokenGrantCredential{"DYNAMIC_TOKEN": {Provider: "acme", CredentialKey: "access", GrantType: "token_exchange"}}}
	s.tokenGrantResolver = tokenGrantResolverFunc(func(_ context.Context, grant TokenGrantCredential, target TokenGrantTarget) (string, error) {
		if grant.Provider != "acme" || grant.CredentialKey != "access" || target.Host != "api.example.com" || target.Path != "/v1/data" {
			t.Fatalf("grant=%+v target=%+v", grant, target)
		}
		return "short-lived-access-token", nil
	})
	req := httptest.NewRequest("GET", "https://api.example.com/v1/data", nil)
	req.Header.Set("Authorization", "Bearer whaleshell:resolve:env:DYNAMIC_TOKEN")
	got, err := s.resolveTokenGrantPlaceholders(context.Background(), "api.example.com", 443, "/v1/data", req, []string{"DYNAMIC_TOKEN"}, SecretStore{"STATIC": "static-token"})
	if err != nil {
		t.Fatal(err)
	}
	if got["DYNAMIC_TOKEN"] != "short-lived-access-token" || got["STATIC"] != "static-token" {
		t.Fatalf("resolved secrets=%v", got)
	}
}

func TestResolveTokenGrantPlaceholdersRejectsUnboundCredentialBeforeExchange(t *testing.T) {
	called := false
	s := &Server{tokenGrants: map[string]TokenGrantCredential{"DYNAMIC_TOKEN": {Provider: "acme"}}, tokenGrantResolver: tokenGrantResolverFunc(func(context.Context, TokenGrantCredential, TokenGrantTarget) (string, error) {
		called = true
		return "token", nil
	})}
	req := httptest.NewRequest("GET", "https://api.example.com/v1/data", nil)
	req.Header.Set("Authorization", "Bearer whaleshell:resolve:env:DYNAMIC_TOKEN")
	_, err := s.resolveTokenGrantPlaceholders(context.Background(), "api.example.com", 443, "/v1/data", req, nil, nil)
	if err == nil || called {
		t.Fatalf("err=%v resolver_called=%v", err, called)
	}
}

func TestSPIFFETokenGrantResolverExpiresCachedToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	resolver := NewSPIFFETokenGrantResolver()
	resolver.Now = func() time.Time { return now }
	grant := TokenGrantCredential{
		Provider:      "acme",
		CredentialKey: "access",
		GrantType:     "client_credentials",
		TokenEndpoint: "https://issuer.example/token",
	}
	target := TokenGrantTarget{Host: "api.example.com", Port: 443, Path: "/v1/data"}
	key := strings.Join([]string{grant.Provider, grant.CredentialKey, grant.TokenEndpoint, "client_credentials", "", "", target.Host, "443", target.Path}, "\x00")
	resolver.cache[key] = cachedGrantToken{value: "cached-access-token", expires: now.Add(time.Minute)}
	t.Setenv("WHALESHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET", "")

	got, err := resolver.ResolveTokenGrant(context.Background(), grant, target)
	if err != nil || got != "cached-access-token" {
		t.Fatalf("cached grant=%q err=%v", got, err)
	}

	now = now.Add(2 * time.Minute)
	if _, err := resolver.ResolveTokenGrant(context.Background(), grant, target); err == nil || !strings.Contains(err.Error(), "SPIFFE Workload API socket is not configured") {
		t.Fatalf("expired cached grant err=%v; want a fresh exchange attempt", err)
	}
}

type tokenGrantWorkloadAPIServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	response *workload.JWTSVIDResponse
	bundles  *workload.JWTBundlesResponse
}

func (s *tokenGrantWorkloadAPIServer) FetchJWTSVID(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return s.response, nil
}

func (s *tokenGrantWorkloadAPIServer) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	if err := stream.Send(s.bundles); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func testSPIFFETokenGrantResolverUsesWorkloadSVIDAndRefreshesAfterExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"sub": "spiffe://example.test/workload",
		"aud": []string{"https://issuer.example/token"},
		"iss": "https://issuer.example",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := compact.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	trustDomain, err := spiffeid.TrustDomainFromString("example.test")
	if err != nil {
		t.Fatal(err)
	}
	bundle := jwtbundle.New(trustDomain)
	if err := bundle.AddJWTAuthority("test-key", &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := bundle.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	socketDir, err := os.MkdirTemp("", "wapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	workloadServer := &tokenGrantWorkloadAPIServer{
		response: &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: "spiffe://example.test/workload", Svid: token}}},
		bundles:  &workload.JWTBundlesResponse{Bundles: map[string][]byte{"example.test": bundleBytes}},
	}
	grpcServer := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(grpcServer, workloadServer)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	source, err := workloadapi.NewJWTSource(context.Background(), workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socket)))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: "https://issuer.example/token"}); err != nil {
		t.Fatalf("fake workload API JWT-SVID: %v", err)
	}

	var calls int
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "assertion=") {
			t.Errorf("token grant body=%q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"access-`+string(rune('0'+calls))+`","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer tokenEndpoint.Close()

	// Do not let an inherited upstream spelling change which socket is tested.
	t.Setenv("OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET", "")
	t.Setenv("WHALESHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET", socket)
	resolver := NewSPIFFETokenGrantResolver()
	now := time.Unix(1_700_000_000, 0)
	resolver.Now = func() time.Time { return now }
	grant := TokenGrantCredential{Provider: "acme", CredentialKey: "access", GrantType: "client_credentials", TokenEndpoint: tokenEndpoint.URL, JWTSVIDAudience: "https://issuer.example/token"}
	target := TokenGrantTarget{Host: "api.example.com", Port: 443, Path: "/v1/data"}
	first, err := resolver.ResolveTokenGrant(context.Background(), grant, target)
	if err != nil || first != "access-1" {
		t.Fatalf("first token=%q calls=%d err=%v", first, calls, err)
	}
	second, err := resolver.ResolveTokenGrant(context.Background(), grant, target)
	if err != nil || second != first || calls != 1 {
		t.Fatalf("cached token=%q calls=%d err=%v", second, calls, err)
	}
	now = now.Add(time.Hour)
	third, err := resolver.ResolveTokenGrant(context.Background(), grant, target)
	if err != nil || third != "access-2" || calls != 2 {
		t.Fatalf("refreshed token=%q calls=%d err=%v", third, calls, err)
	}
}

func TestTokenGrantTargetAppliesAudienceAndScopeOverride(t *testing.T) {
	g := TokenGrantCredential{Audience: "default", Scopes: []string{"read"}, AudienceOverrides: []TokenGrantAudienceOverride{{Host: "api.example.com", Port: 443, Path: "/admin/**", Audience: "admin-aud", Scopes: []string{"write"}}}}
	aud, scopes := tokenGrantTarget(g, TokenGrantTarget{Host: "api.example.com", Port: 443, Path: "/admin/users"})
	if aud != "admin-aud" || len(scopes) != 1 || scopes[0] != "write" {
		t.Fatalf("aud=%q scopes=%v", aud, scopes)
	}
	aud, scopes = tokenGrantTarget(g, TokenGrantTarget{Host: "api.example.com", Port: 443, Path: "/public"})
	if aud != "default" || len(scopes) != 1 || scopes[0] != "read" {
		t.Fatalf("default aud=%q scopes=%v", aud, scopes)
	}
}
