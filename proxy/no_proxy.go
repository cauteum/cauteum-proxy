package proxy

import (
	"net/netip"
	"strconv"
	"strings"
)

type noProxyKind uint8

const (
	noProxyDomain noProxyKind = iota
	noProxyIP
	noProxyCIDR
	noProxyAll
)

type noProxyEntry struct {
	kind    noProxyKind
	domain  string
	ip      netip.Addr
	prefix  netip.Prefix
	port    uint16
	hasPort bool
}

// noProxyAddresses implements the OpenShell upstream-proxy bypass grammar:
// wildcard, domain suffix, IP/CIDR and optional port. The caller passes only
// addresses already resolved and approved by the SSRF policy, so bypassing a
// corporate proxy cannot bypass Whaleshell's destination policy.
func noProxyAddresses(host string, port uint16, raw string, resolved []netip.Addr) []netip.Addr {
	entries := parseNoProxy(raw)
	canonicalHost := strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]")), ".")
	if ip, err := netip.ParseAddr(canonicalHost); err == nil {
		canonicalHost = ip.Unmap().String()
	}
	var direct []netip.Addr
	for _, entry := range entries {
		if entry.hasPort && entry.port != port {
			continue
		}
		switch entry.kind {
		case noProxyAll:
			return append([]netip.Addr(nil), resolved...)
		case noProxyDomain:
			if canonicalHost == entry.domain || strings.HasSuffix(canonicalHost, "."+entry.domain) {
				return append([]netip.Addr(nil), resolved...)
			}
		case noProxyIP:
			if ip, err := netip.ParseAddr(canonicalHost); err == nil && ip.Unmap() == entry.ip {
				return append([]netip.Addr(nil), resolved...)
			}
			for _, addr := range resolved {
				if addr.Unmap() == entry.ip {
					direct = appendUniqueAddr(direct, addr)
				}
			}
		case noProxyCIDR:
			if ip, err := netip.ParseAddr(canonicalHost); err == nil && entry.prefix.Contains(ip.Unmap()) {
				return append([]netip.Addr(nil), resolved...)
			}
			for _, addr := range resolved {
				if entry.prefix.Contains(addr.Unmap()) {
					direct = appendUniqueAddr(direct, addr)
				}
			}
		}
	}
	return direct
}

func parseNoProxy(raw string) []noProxyEntry {
	var entries []noProxyEntry
	for _, token := range strings.Split(raw, ",") {
		item := strings.TrimSpace(token)
		if item == "" {
			continue
		}
		if item == "*" {
			entries = append(entries, noProxyEntry{kind: noProxyAll})
			continue
		}
		item = strings.ToLower(item)
		if prefix, err := netip.ParsePrefix(item); err == nil {
			entries = append(entries, noProxyEntry{kind: noProxyCIDR, prefix: prefix.Masked()})
			continue
		}
		if ip, err := netip.ParseAddr(strings.Trim(item, "[]")); err == nil {
			entries = append(entries, noProxyEntry{kind: noProxyIP, ip: ip.Unmap()})
			continue
		}
		head, port, hasPort := splitNoProxyPort(item)
		if prefix, err := netip.ParsePrefix(head); err == nil {
			entries = append(entries, noProxyEntry{kind: noProxyCIDR, prefix: prefix.Masked(), port: port, hasPort: hasPort})
			continue
		}
		if ip, err := netip.ParseAddr(strings.Trim(head, "[]")); err == nil {
			entries = append(entries, noProxyEntry{kind: noProxyIP, ip: ip.Unmap(), port: port, hasPort: hasPort})
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(head, "*."), "."), ".")
		if name != "" {
			entries = append(entries, noProxyEntry{kind: noProxyDomain, domain: name, port: port, hasPort: hasPort})
		}
	}
	return entries
}

func splitNoProxyPort(item string) (string, uint16, bool) {
	var head, suffix string
	if strings.HasPrefix(item, "[") {
		close := strings.LastIndex(item, "]:")
		if close < 0 {
			return item, 0, false
		}
		head, suffix = item[:close+1], item[close+2:]
	} else {
		colon := strings.LastIndexByte(item, ':')
		if colon < 0 {
			return item, 0, false
		}
		head, suffix = item[:colon], item[colon+1:]
	}
	n, err := strconv.ParseUint(suffix, 10, 16)
	if err != nil || n == 0 {
		return item, 0, false
	}
	if _, err := netip.ParsePrefix(head); err != nil {
		if _, err := netip.ParseAddr(strings.Trim(head, "[]")); err != nil && strings.Contains(head, ":") {
			return item, 0, false
		}
	}
	return head, uint16(n), true
}

func appendUniqueAddr(addrs []netip.Addr, candidate netip.Addr) []netip.Addr {
	for _, addr := range addrs {
		if addr == candidate {
			return addrs
		}
	}
	return append(addrs, candidate)
}
