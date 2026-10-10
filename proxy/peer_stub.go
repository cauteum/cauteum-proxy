//go:build !linux

package proxy

import "net"

func peerExecutable(c net.Conn) string {
	_ = c
	return ""
}
