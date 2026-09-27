package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
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

func TestDialViaUpstreamProxyRejectsAllowedIPs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "http://"+listener.Addr().String())
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	_, err = DialSSRF(context.Background(), "127.0.0.1", "443", SSRFOptions{
		allowLoopback: true,
		AllowedIPs:    []string{"127.0.0.0/8"},
	})
	if err == nil || !strings.Contains(err.Error(), "refusing proxy dial") {
		t.Fatalf("expected fail-closed proxy route, got %v", err)
	}
}
