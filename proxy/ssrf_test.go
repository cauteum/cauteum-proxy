package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestSSRFBlocksLoopback(t *testing.T) {
	_, err := ResolveAndFilter(context.Background(), "127.0.0.1", SSRFOptions{})
	if err == nil {
		t.Fatal("expected loopback block")
	}
}

func TestSSRFBlocksPrivateWithoutAllow(t *testing.T) {
	_, err := ResolveAndFilter(context.Background(), "10.1.2.3", SSRFOptions{})
	if err == nil {
		t.Fatal("expected private block")
	}
}

func TestSSRFAllowsPrivateWithCIDR(t *testing.T) {
	addrs, err := ResolveAndFilter(context.Background(), "10.1.2.3", SSRFOptions{
		AllowedIPs: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestSSRFAllowLoopbackOpt(t *testing.T) {
	addrs, err := ResolveAndFilter(context.Background(), "127.0.0.1", SSRFOptions{allowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestSSRFLinkLocalAlwaysBlocked(t *testing.T) {
	_, err := ResolveAndFilter(context.Background(), "169.254.169.254", SSRFOptions{
		AllowedIPs: []string{"169.254.0.0/16"},
	})
	if err == nil {
		t.Fatal("link-local must stay blocked")
	}
}

func TestSSRFAlwaysBlockedRangesIgnoreAllowedIPs(t *testing.T) {
	for _, addr := range []string{
		"0.1.2.3", "100.64.0.1", "192.0.0.1", "198.18.0.1",
		"224.0.0.1", "::", "ff02::1", "::ffff:127.0.0.1",
	} {
		t.Run(addr, func(t *testing.T) {
			_, err := ResolveAndFilter(context.Background(), addr, SSRFOptions{
				AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			})
			if err == nil {
				t.Fatal("reserved address must stay blocked")
			}
		})
	}
}

func TestDialSSRFResolvesOnceAndUsesFilteredAddress(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(key, "")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	conn, err := DialSSRF(context.Background(), "rebind.example", port, SSRFOptions{
		allowLoopback: true,
		LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			lookups++
			if lookups > 1 {
				return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("169.254.169.254")}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if lookups != 1 {
		t.Fatalf("DNS lookups = %d, want 1", lookups)
	}
}
