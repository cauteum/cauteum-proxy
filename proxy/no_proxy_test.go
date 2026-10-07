package proxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func addrList(values ...string) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addrs = append(addrs, netip.MustParseAddr(value))
	}
	return addrs
}

func TestNoProxyOpenShellCompatibility(t *testing.T) {
	tests := []struct {
		name, host, list string
		port             uint16
		resolved         []netip.Addr
		want             []netip.Addr
	}{
		{name: "domain exact", host: "corp.com", list: "corp.com", port: 443, resolved: addrList("8.8.8.8"), want: addrList("8.8.8.8")},
		{name: "domain suffix", host: "api.corp.com", list: "corp.com", port: 443, resolved: addrList("8.8.8.8"), want: addrList("8.8.8.8")},
		{name: "no partial suffix", host: "notcorp.com", list: "corp.com", port: 443, resolved: addrList("8.8.8.8")},
		{name: "leading dot", host: "api.svc.local", list: ".svc.local", port: 443, resolved: addrList("8.8.8.8"), want: addrList("8.8.8.8")},
		{name: "wildcard prefix", host: "api.svc.local", list: "*.svc.local", port: 443, resolved: addrList("8.8.8.8"), want: addrList("8.8.8.8")},
		{name: "wildcard all", host: "anything.invalid", list: "*", port: 443, resolved: addrList("8.8.8.8"), want: addrList("8.8.8.8")},
		{name: "exact IP", host: "192.168.1.5", list: "192.168.1.5", port: 443, resolved: addrList("192.168.1.5"), want: addrList("192.168.1.5")},
		{name: "IPv4 CIDR literal", host: "10.96.1.2", list: "10.96.0.0/12", port: 443, resolved: addrList("10.96.1.2"), want: addrList("10.96.1.2")},
		{name: "CIDR resolves hostname", host: "svc.cluster", list: "10.96.0.0/12", port: 443, resolved: addrList("8.8.8.8", "10.96.1.2"), want: addrList("10.96.1.2")},
		{name: "CIDR limits matched resolved addresses", host: "svc.cluster", list: "10.96.0.0/12", port: 443, resolved: addrList("10.96.1.2", "10.120.1.2"), want: addrList("10.96.1.2")},
		{name: "port qualifier matches", host: "api.corp.com", list: "corp.com:8443", port: 8443, resolved: addrList("8.8.8.8"), want: addrList("8.8.8.8")},
		{name: "port qualifier scopes domain", host: "api.corp.com", list: "corp.com:8443", port: 443, resolved: addrList("8.8.8.8")},
		{name: "port qualifier IP", host: "192.168.1.5", list: "192.168.1.5:8443", port: 8443, resolved: addrList("192.168.1.5"), want: addrList("192.168.1.5")},
		{name: "port qualifier CIDR", host: "svc.cluster", list: "10.96.0.0/12:6443", port: 6443, resolved: addrList("10.96.1.2"), want: addrList("10.96.1.2")},
		{name: "invalid port not stripped", host: "corp.com", list: "corp.com:99999", port: 443, resolved: addrList("8.8.8.8")},
		{name: "bracketed IPv6 port", host: "fd00::1", list: "[fd00::1]:8443", port: 8443, resolved: addrList("fd00::1"), want: addrList("fd00::1")},
		{name: "IPv6 CIDR resolves hostname", host: "svc.cluster", list: "fd00::/8", port: 443, resolved: addrList("2001:db8::1", "fd00::42"), want: addrList("fd00::42")},
		{name: "IPv6 CIDR port", host: "svc.cluster", list: "fd00::/8:6443", port: 6443, resolved: addrList("fd00::42"), want: addrList("fd00::42")},
		{name: "no resolved address cannot bypass", host: "corp.com", list: "corp.com", port: 443},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := noProxyAddresses(tt.host, tt.port, tt.list, tt.resolved)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("noProxyAddresses(%q, %d, %q) = %v; want %v", tt.host, tt.port, tt.list, got, tt.want)
			}
		})
	}
}

func TestDialSSRFNoProxyUsesExactHostAndPort(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	_, targetPort, _ := net.SplitHostPort(target.Addr().String())
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr == nil {
			_, _ = io.WriteString(conn, "direct")
			_ = conn.Close()
		}
	}()

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyUsed := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := proxy.Accept()
		if acceptErr == nil {
			proxyUsed <- struct{}{}
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			_ = conn.Close()
		}
	}()

	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "http://"+proxy.Addr().String())
	}
	t.Setenv("NO_PROXY", "127.0.0.1:"+targetPort)
	if runtime.GOOS != "windows" {
		t.Setenv("no_proxy", "")
	}
	conn, err := DialSSRF(context.Background(), "127.0.0.1", targetPort, SSRFOptions{allowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil || string(data) != "direct" {
		t.Fatalf("exact no_proxy target data=%q err=%v", data, err)
	}
	select {
	case <-proxyUsed:
		t.Fatal("exact no_proxy target unexpectedly used upstream proxy")
	default:
	}

	// A different port must not inherit the host-only bypass.
	secondTarget, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer secondTarget.Close()
	_, secondPort, _ := net.SplitHostPort(secondTarget.Addr().String())
	if secondPort == targetPort {
		t.Fatal("test listeners unexpectedly reused the same port")
	}
	t.Setenv("NO_PROXY", "127.0.0.1:1")
	_, err = DialSSRF(context.Background(), "127.0.0.1", secondPort, SSRFOptions{allowLoopback: true})
	if err == nil || !strings.Contains(err.Error(), "upstream proxy") {
		t.Fatalf("non-matching port did not use upstream proxy: %v", err)
	}
	select {
	case <-proxyUsed:
	case <-time.After(time.Second):
		t.Fatal("non-matching port did not reach upstream proxy")
	}
}
