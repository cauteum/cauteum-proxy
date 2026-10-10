package proxy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendEgressCertsRejectsMalformedBundle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	valid := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})

	for name, bundle := range map[string][]byte{
		"empty":            nil,
		"wrong block":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}),
		"trailing garbage": append(append([]byte(nil), valid...), []byte("garbage")...),
		"invalid DER":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := appendEgressCerts(x509.NewCertPool(), bundle); err == nil {
				t.Fatal("malformed CA bundle accepted")
			}
		})
	}

	roots := x509.NewCertPool()
	if err := appendEgressCerts(roots, valid); err != nil {
		t.Fatal(err)
	}
	if len(roots.Subjects()) != 1 {
		t.Fatalf("CA bundle added %d certificates, want 1", len(roots.Subjects()))
	}
}

func TestInvalidEgressCABundleFailsBeforeProxyListen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAUTEUM_EGRESS_CA_BUNDLE", path)
	proxy := NewServer(nil, io.Discard)
	if proxy.UpstreamTLS != nil {
		t.Fatal("invalid CA bundle configured upstream TLS")
	}
	err := proxy.ListenAndServe(context.Background(), "127.0.0.1:0")
	if err == nil || !strings.Contains(err.Error(), "configured egress CA bundle is invalid") {
		t.Fatalf("proxy startup error = %v, want invalid CA bundle", err)
	}
}
