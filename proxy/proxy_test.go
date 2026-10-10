package proxy_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-core/engine"
	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-proxy/proxy"
)

func TestCONNECTAllowDeny(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
	}()
	_, backendPort, _ := net.SplitHostPort(backend.Addr().String())

	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{
		{ID: "local", Host: "127.0.0.1", Port: mustAtoi(backendPort)},
	})
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	srv := proxy.NewServerForTests(&eng, io.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := t.Context()
	go func() { _ = srv.Serve(ctx, ln) }()

	proxyAddr := ln.Addr().String()

	t.Run("allow", func(t *testing.T) {
		body, status := rawCONNECT(t, proxyAddr, net.JoinHostPort("127.0.0.1", backendPort))
		if status != 200 {
			t.Fatalf("status=%d body=%q", status, body)
		}
		if !strings.Contains(body, "hello") {
			t.Fatalf("tunnel body=%q", body)
		}
	})

	t.Run("deny", func(t *testing.T) {
		body, status := rawCONNECT(t, proxyAddr, "example.com:443")
		if status != 403 {
			t.Fatalf("status=%d body=%q", status, body)
		}
	})
}

func TestCONNECTTLSkipWithL7ConfigUsesRawTunnel(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("raw-tunnel"))
	}()
	host, portText, err := net.SplitHostPort(backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := mustAtoi(portText)
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		ID: "explicit-tls-skip", Host: host, Port: port,
		Protocol: policy.ProtocolREST, TLS: "skip", Access: policy.AccessReadOnly,
	}})
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatalf("apply TLS skip policy: %v", err)
	}
	srv := proxy.NewServerForTests(&eng, io.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = srv.Serve(t.Context(), ln) }()

	body, status := rawCONNECT(t, ln.Addr().String(), net.JoinHostPort(host, portText))
	if status != http.StatusOK || !strings.Contains(body, "raw-tunnel") {
		t.Fatalf("CONNECT status=%d body=%q, want raw tunnel", status, body)
	}
}

func rawCONNECT(t *testing.T, proxyAddr, target string) (string, int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return string(b), resp.StatusCode
	}
	buf := make([]byte, 64)
	n, _ := br.Read(buf)
	return string(buf[:n]), resp.StatusCode
}

func TestAbsoluteFormL7(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("l7-ok"))
	})
	backend := &http.Server{Handler: mux}
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bln.Close()
	go func() { _ = backend.Serve(bln) }()
	defer backend.Close()
	_, bport, _ := net.SplitHostPort(bln.Addr().String())

	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		ID:       "local",
		Host:     "127.0.0.1",
		Port:     mustAtoi(bport),
		Protocol: "rest",
		Access:   "read-only",
	}})
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	srv := proxy.NewServerForTests(&eng, io.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := t.Context()
	go func() { _ = srv.Serve(ctx, ln) }()

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("http://" + ln.Addr().String()))},
		Timeout:   3 * time.Second,
	}

	t.Run("get_allow", func(t *testing.T) {
		res, err := client.Get("http://127.0.0.1:" + bport + "/ok")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 || string(b) != "l7-ok" {
			t.Fatalf("status=%d body=%q", res.StatusCode, b)
		}
	})
	t.Run("post_deny", func(t *testing.T) {
		res, err := client.Post("http://127.0.0.1:"+bport+"/ok", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("status=%d want 403", res.StatusCode)
		}
	})
}

func TestTLSPassthroughAliasAutoTerminatesL7(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("mitm-ok"))
	})
	origin := &http.Server{Handler: mux}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawLn.Close()
	tlsLn := tls.NewListener(rawLn, &tls.Config{
		Certificates: []tls.Certificate{mustSelfSigned(t)},
		NextProtos:   []string{"http/1.1"},
	})
	go func() { _ = origin.Serve(tlsLn) }()
	defer origin.Close()
	_, oport, _ := net.SplitHostPort(rawLn.Addr().String())

	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		ID:       "local",
		Host:     "127.0.0.1",
		Port:     mustAtoi(oport),
		Protocol: "rest",
		TLS:      "passthrough",
		Access:   "read-only",
	}})
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	srv := proxy.NewServerForTests(&eng, io.Discard)
	srv.UpstreamTLS = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	ca := srv.CA()
	if ca == nil {
		t.Fatal("expected MITM CA")
	}

	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	ctx := t.Context()
	go func() { _ = srv.Serve(ctx, pln) }()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustURL("http://" + pln.Addr().String())),
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.RootPool(),
				NextProtos: []string{"http/1.1"},
			},
		},
		Timeout: 5 * time.Second,
	}

	t.Run("get_allow", func(t *testing.T) {
		res, err := client.Get("https://127.0.0.1:" + oport + "/ok")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 || string(b) != "mitm-ok" {
			t.Fatalf("status=%d body=%q", res.StatusCode, b)
		}
	})
	t.Run("post_deny", func(t *testing.T) {
		res, err := client.Post("https://127.0.0.1:"+oport+"/ok", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("status=%d want 403", res.StatusCode)
		}
	})
}

func TestTLSAutoDetectionForL4OnlyCONNECT(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("auto-tls-ok"))
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(originURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{ID: "l4", Host: host, Port: mustAtoi(portText)}})
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatalf("apply L4 policy: %v", err)
	}
	srv := proxy.NewServerForTests(&eng, io.Discard)
	srv.UpstreamTLS = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	ca := srv.CA()
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	go func() { _ = srv.Serve(t.Context(), pln) }()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustURL("http://" + pln.Addr().String())),
			TLSClientConfig: &tls.Config{RootCAs: ca.RootPool(), NextProtos: []string{"http/1.1"}},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "auto-tls-ok" {
		t.Fatalf("status=%d body=%q, want successful TLS auto-detected response", resp.StatusCode, body)
	}
}

func mustSelfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	ca, err := proxy.GenerateMitmCA()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return *leaf
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func mustAtoi(s string) int {
	var n int
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func TestCONNECTSQLAuditPassesTLSBytesWithoutHTTPMITM(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	host, portText, err := net.SplitHostPort(backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := mustAtoi(portText)
	received := make(chan []byte, 1)
	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		payload := make([]byte, 6)
		if _, readErr := io.ReadFull(conn, payload); readErr == nil {
			received <- payload
		}
	}()
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: host, Port: port, Protocol: policy.ProtocolSQL, Enforcement: policy.EnforcementAudit,
		Rules: []policy.L7Rule{{Allow: &policy.L7Allow{Command: "SELECT"}}},
	}})
	var eng engine.Allowlist
	if err = eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	auditLines := make(chan string, 4)
	srv := proxy.NewServerForTests(&eng, auditLineWriter(auditLines))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = srv.Serve(t.Context(), listener) }()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	target := net.JoinHostPort(host, portText)
	if _, err = io.WriteString(client, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d", response.StatusCode)
	}
	helloPrefix := []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x00}
	if _, err = client.Write(helloPrefix); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, helloPrefix) {
			t.Fatalf("backend bytes=%x want=%x", got, helloPrefix)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive TLS record bytes through SQL audit tunnel")
	}
	deadline := time.After(time.Second)
	for {
		select {
		case line := <-auditLines:
			if strings.Contains(line, "SQL command inspection is unavailable") {
				return
			}
		case <-deadline:
			t.Fatal("missing SQL audit-only diagnostic")
		}
	}
}

type auditLineWriter chan string

func (w auditLineWriter) Write(p []byte) (int, error) {
	w <- string(p)
	return len(p), nil
}
