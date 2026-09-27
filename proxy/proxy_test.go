package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/whaleshell/whaleshell-core/engine"
	"github.com/whaleshell/whaleshell-core/policy"
	"github.com/whaleshell/whaleshell-proxy/proxy"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

func TestTLSTerminateL7(t *testing.T) {
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
		TLS:      "terminate",
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
