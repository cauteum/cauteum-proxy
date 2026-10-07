package proxy

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDialViaUpstreamProxy(t *testing.T) {
	// Fake corp proxy: accepts CONNECT and tunnels to a backend.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("upstream-ok"))
	}()
	_, bport, _ := net.SplitHostPort(backend.Addr().String())

	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	go func() {
		c, err := pln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		up, err := net.DialTimeout("tcp", req.Host, time.Second)
		if err != nil {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer up.Close()
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, br) }()
		_, _ = io.Copy(c, up)
	}()

	t.Setenv("HTTP_PROXY", "http://"+pln.Addr().String())
	t.Setenv("HTTPS_PROXY", "http://"+pln.Addr().String())
	t.Setenv("NO_PROXY", "")

	conn, err := DialSSRF(context.Background(), "127.0.0.1", bport, SSRFOptions{allowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "upstream-ok") {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestDialViaUpstreamProxyUsesAuthFileWithoutEmbeddingSecretInURL(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	got := make(chan *http.Request, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err == nil {
			got <- req
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		}
	}()
	authPath := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(authPath, []byte("robot:s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTPS_PROXY", "http://"+listener.Addr().String())
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("WHALESHELL_PROXY_AUTH_FILE", authPath)
	t.Setenv("WHALESHELL_PROXY_CONNECT_BY_HOSTNAME", "false")
	t.Setenv("WHALESHELL_PROXY_CA_BUNDLE", "")
	conn, err := DialSSRF(context.Background(), "api.example.com", "443", SSRFOptions{LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	req := <-got
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("robot:s3cret"))
	if req.Host != "8.8.8.8:443" || req.Header.Get("Proxy-Authorization") != want {
		t.Fatalf("CONNECT host=%q auth=%q", req.Host, req.Header.Get("Proxy-Authorization"))
	}
}

func TestDialViaHTTPSProxyUsesConfiguredCABundle(t *testing.T) {
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = rw.Flush()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}))
	proxy.StartTLS()
	defer proxy.Close()
	caPath := filepath.Join(t.TempDir(), "proxy-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})
	if _, err := x509.ParseCertificate(proxy.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTPS_PROXY", strings.Replace(proxy.URL, "https://", "https://", 1))
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("WHALESHELL_PROXY_AUTH_FILE", "")
	t.Setenv("WHALESHELL_PROXY_CONNECT_BY_HOSTNAME", "false")
	t.Setenv("WHALESHELL_PROXY_CA_BUNDLE", caPath)
	conn, err := DialSSRF(context.Background(), "api.example.com", "443", SSRFOptions{LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestDialViaUpstreamProxyUsesValidatedIPAndRejectsHostnameModeWithAllowedIPs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err == nil {
			target <- req.Host
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		}
	}()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "http://"+listener.Addr().String())
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	for _, key := range []string{"WHALESHELL_PROXY_CONNECT_BY_HOSTNAME", "WHALESHELL_PROXY_AUTH_FILE", "WHALESHELL_PROXY_CA_BUNDLE"} {
		t.Setenv(key, "")
	}
	resolver := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	conn, err := DialSSRF(context.Background(), "api.example.com", "443", SSRFOptions{
		AllowedIPs:   []string{"8.8.8.8/32"},
		LookupIPAddr: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := <-target; got != "8.8.8.8:443" {
		t.Fatalf("CONNECT target=%q, want validated IP", got)
	}
	t.Setenv("WHALESHELL_PROXY_CONNECT_BY_HOSTNAME", "true")
	_, err = DialSSRF(context.Background(), "api.example.com", "443", SSRFOptions{AllowedIPs: []string{"8.8.8.8/32"}, LookupIPAddr: resolver})
	if err == nil || !strings.Contains(err.Error(), "hostname CONNECT") {
		t.Fatalf("expected hostname mode to fail closed with allowed IPs, got %v", err)
	}
}
