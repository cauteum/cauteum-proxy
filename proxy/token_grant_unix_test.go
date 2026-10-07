//go:build !windows

package proxy

import "testing"

func TestSPIFFETokenGrantResolverUsesWorkloadSVIDAndRefreshesAfterExpiry(t *testing.T) {
	testSPIFFETokenGrantResolverUsesWorkloadSVIDAndRefreshesAfterExpiry(t)
}
