package proxy

import (
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLeafCachedWhileFresh(t *testing.T) {
	ca, err := GenerateMitmCA()
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.Leaf("github.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ca.Leaf("GitHub.com")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("expected cached leaf for the same host")
	}
	if first.Leaf == nil {
		t.Fatal("expected parsed x509 leaf")
	}
}

func TestLeafCacheEvictsOnlyLeastRecentlyUsed(t *testing.T) {
	ca, err := GenerateMitmCA()
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.Leaf("first.example")
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxCachedLeafs - 1 {
		if _, err := ca.Leaf(fmt.Sprintf("host-%d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	if again, err := ca.Leaf("first.example"); err != nil || again != first {
		t.Fatalf("recent leaf lost: %v", err)
	}
	if _, err := ca.Leaf("overflow.example"); err != nil {
		t.Fatal(err)
	}
	if again, err := ca.Leaf("first.example"); err != nil || again != first {
		t.Fatalf("LRU evicted recently used leaf: %v", err)
	}
	if ca.lru.Len() != maxCachedLeafs {
		t.Fatalf("cache size %d", ca.lru.Len())
	}
}

func TestConcurrentLeafGenerationSharesResult(t *testing.T) {
	ca, err := GenerateMitmCA()
	if err != nil {
		t.Fatal(err)
	}
	const callers = 16
	var group sync.WaitGroup
	results := make([]*tls.Certificate, callers)
	for i := range callers {
		group.Go(func() {
			results[i], _ = ca.Leaf("same.example")
		})
	}
	group.Wait()
	for _, cert := range results {
		if cert == nil || cert != results[0] {
			t.Fatal("concurrent callers did not share a leaf")
		}
	}
}

func TestLeafReissuedNearExpiry(t *testing.T) {
	ca, err := GenerateMitmCA()
	if err != nil {
		t.Fatal(err)
	}
	stale, err := ca.Leaf("github.com")
	if err != nil {
		t.Fatal(err)
	}
	stale.Leaf.NotAfter = time.Now().Add(leafRenewBefore / 2)

	fresh, err := ca.Leaf("github.com")
	if err != nil {
		t.Fatal(err)
	}
	if fresh == stale {
		t.Fatal("expected a new leaf once the cached one is near expiry")
	}
	if time.Until(fresh.Leaf.NotAfter) <= leafRenewBefore {
		t.Fatalf("new leaf expires too soon: %s", fresh.Leaf.NotAfter)
	}
}
