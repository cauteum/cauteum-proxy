package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Always-blocked ranges (SSRF): never allowed, not even via allowed_ips.
// allowLoopback bypasses only 127.0.0.0/8 + ::1/128 for tests; everything
// else below stays blocked unconditionally.
var (
	cidrLoopback4   = mustCIDR("127.0.0.0/8")
	cidrLoopback6   = mustCIDR("::1/128")
	cidrLinkLocal4  = mustCIDR("169.254.0.0/16")
	cidrLinkLocal6  = mustCIDR("fe80::/10")
	cidrUnspecified = mustCIDR("0.0.0.0/8")
	cidrCGNAT       = mustCIDR("100.64.0.0/10")
	cidrIETF1       = mustCIDR("192.0.0.0/24")
	cidrBench       = mustCIDR("198.18.0.0/15")
	cidrMulticast4  = mustCIDR("224.0.0.0/4")
	cidrUnspec6     = mustCIDR("::/128")
	cidrMapped4     = mustCIDR("::ffff:0:0/96")
	cidrMulticast6  = mustCIDR("ff00::/8")
	cidrPrivate10   = mustCIDR("10.0.0.0/8")
	cidrPrivate172  = mustCIDR("172.16.0.0/12")
	cidrPrivate192  = mustCIDR("192.168.0.0/16")
	cidrULA         = mustCIDR("fc00::/7")
)

func mustCIDR(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// SSRFOptions controls destination IP checks before dial.
type SSRFOptions struct {
	AllowedIPs    []string
	allowLoopback bool // test-only; never set by production callers
	// LookupIPAddr overrides DNS resolution (tests inject a fake resolver to
	// simulate DNS rebinding). Nil means net.DefaultResolver.
	LookupIPAddr func(ctx context.Context, host string) ([]net.IPAddr, error)
}

// lookupIP resolves host to IPs, honoring opts.LookupIPAddr when set.
func lookupIP(ctx context.Context, host string, opts SSRFOptions) ([]net.IPAddr, error) {
	if opts.LookupIPAddr != nil {
		return opts.LookupIPAddr(ctx, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// ResolveAndFilter returns dialable IPs for host after SSRF checks.
func ResolveAndFilter(ctx context.Context, host string, opts SSRFOptions) ([]netip.Addr, error) {
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		ips, err := lookupIP(ctx, host, opts)
		if err != nil {
			return nil, fmt.Errorf("ssrf resolve %q: %w", host, err)
		}
		for _, ipa := range ips {
			addr, ok := netip.AddrFromSlice(ipa.IP)
			if !ok {
				continue
			}
			addrs = append(addrs, addr.Unmap())
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("ssrf: no addresses for %q", host)
	}

	allowNets, err := parseAllowNets(opts.AllowedIPs)
	if err != nil {
		return nil, err
	}

	var out []netip.Addr
	for _, addr := range addrs {
		if isLoopback(addr) {
			if !opts.allowLoopback {
				continue
			}
			out = append(out, addr)
			continue
		}
		if alwaysBlocked(addr) {
			continue
		}
		priv := isPrivate(addr)
		if len(allowNets) > 0 {
			if !ipInAny(addr, allowNets) {
				continue
			}
			out = append(out, addr)
			continue
		}
		if priv {
			continue
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ssrf: blocked all addresses for %q (private/loopback/link-local without allowed_ips)", host)
	}
	return out, nil
}

// DialSSRF resolves host once, applies SSRF filters, then dials only the
// filtered addresses (no second lookup — DNS-rebinding TOCTOU safe).
// When HTTP_PROXY/HTTPS_PROXY is set, opens a CONNECT tunnel through the corp
// proxy to host:port. The corp proxy is a trusted boundary: it sees the raw
// target, so combining it with policy AllowedIPs is fail-closed (refused) and
// the dial is audit-logged as via-proxy.
func DialSSRF(ctx context.Context, host, port string, opts SSRFOptions) (net.Conn, error) {
	addrs, err := ResolveAndFilter(ctx, host, opts)
	if err != nil {
		return nil, err
	}
	proxyURL, bypass := upstreamProxyURL(host, port, addrs)
	if proxyURL != nil {
		targetHost := addrs[0].String()
		if strings.EqualFold(strings.TrimSpace(os.Getenv("CAUTEUM_PROXY_CONNECT_BY_HOSTNAME")), "true") {
			if len(opts.AllowedIPs) > 0 {
				return nil, fmt.Errorf("ssrf: hostname CONNECT through an upstream proxy is incompatible with allowed_ips")
			}
			targetHost = host
		}
		return dialViaHTTPProxy(ctx, proxyURL, net.JoinHostPort(targetHost, port))
	}
	if len(bypass) != 0 {
		addrs = bypass
	}
	var last error
	d := net.Dialer{Timeout: upstreamDialTimeout}
	for _, addr := range addrs {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), port))
		if err != nil {
			last = err
			continue
		}
		return c, nil
	}
	if last == nil {
		last = fmt.Errorf("ssrf: dial failed")
	}
	return nil, last
}

func upstreamProxyURL(destHost, destPort string, addrs []netip.Addr) (*url.URL, []netip.Addr) {
	parsedPort, _ := strconv.ParseUint(destPort, 10, 16)
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		if parsedPort != 0 {
			if direct := noProxyAddresses(destHost, uint16(parsedPort), os.Getenv("NO_PROXY")+","+os.Getenv("no_proxy"), addrs); len(direct) > 0 {
				return nil, direct
			}
		}
		return u, nil
	}
	return nil, nil
}

func dialViaHTTPProxy(ctx context.Context, proxyURL *url.URL, target string) (net.Conn, error) {
	addr := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			addr = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			addr = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}
	d := net.Dialer{Timeout: upstreamDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy dial: %w", err)
	}
	if strings.EqualFold(proxyURL.Scheme, "https") {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: proxyURL.Hostname()}
		if caPath := strings.TrimSpace(os.Getenv("CAUTEUM_PROXY_CA_BUNDLE")); caPath != "" {
			body, readErr := os.ReadFile(caPath)
			if readErr != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("read upstream proxy CA bundle")
			}
			roots, poolErr := x509.SystemCertPool()
			if poolErr != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(body) {
				_ = conn.Close()
				return nil, fmt.Errorf("upstream proxy CA bundle contains no certificates")
			}
			tlsConfig.RootCAs = roots
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("upstream proxy TLS handshake failed")
		}
		conn = tlsConn
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
		Proto:  "HTTP/1.1",
	}
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	} else if authPath := strings.TrimSpace(os.Getenv("CAUTEUM_PROXY_AUTH_FILE")); authPath != "" {
		body, err := os.ReadFile(authPath)
		if err != nil || len(body) > 64*1024 {
			_ = conn.Close()
			return nil, fmt.Errorf("read upstream proxy auth file")
		}
		username, password, ok := strings.Cut(strings.TrimSpace(string(body)), ":")
		if !ok || strings.TrimSpace(username) == "" {
			_ = conn.Close()
			return nil, fmt.Errorf("upstream proxy auth file must contain user:pass")
		}
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream proxy response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT: %s", resp.Status)
	}
	if br.Buffered() > 0 {
		return &bufConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

func parseAllowNets(cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("ssrf allowed_ips: invalid %q", s)
		}
		bits := ip.BitLen()
		out = append(out, netip.PrefixFrom(ip, bits))
	}
	return out, nil
}

func alwaysBlocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	return cidrLoopback4.Contains(addr) || cidrLoopback6.Contains(addr) ||
		cidrLinkLocal4.Contains(addr) || cidrLinkLocal6.Contains(addr) ||
		cidrUnspecified.Contains(addr) || cidrCGNAT.Contains(addr) ||
		cidrIETF1.Contains(addr) || cidrBench.Contains(addr) ||
		cidrMulticast4.Contains(addr) || cidrUnspec6.Contains(addr) ||
		cidrMapped4.Contains(addr) || cidrMulticast6.Contains(addr)
}

// isLoopback reports loopback only (the single range test-only bypasses).
func isLoopback(addr netip.Addr) bool {
	addr = addr.Unmap()
	return cidrLoopback4.Contains(addr) || cidrLoopback6.Contains(addr)
}

func isPrivate(addr netip.Addr) bool {
	addr = addr.Unmap()
	return cidrPrivate10.Contains(addr) || cidrPrivate172.Contains(addr) ||
		cidrPrivate192.Contains(addr) || cidrULA.Contains(addr)
}

func ipInAny(addr netip.Addr, nets []netip.Prefix) bool {
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}
