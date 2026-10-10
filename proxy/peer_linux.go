//go:build linux

package proxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func peerExecutable(c net.Conn) string {
	pid, err := peerPID(c)
	if err != nil || pid <= 0 {
		return ""
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return filepath.Clean(target)
}

func peerPID(c net.Conn) (int, error) {
	var rc syscall.RawConn
	switch t := c.(type) {
	case *net.TCPConn:
		sys, err := t.SyscallConn()
		if err != nil {
			return 0, err
		}
		rc = sys
	case *net.UnixConn:
		sys, err := t.SyscallConn()
		if err != nil {
			return 0, err
		}
		rc = sys
	default:
		if sc, ok := c.(interface {
			SyscallConn() (syscall.RawConn, error)
		}); ok {
			sys, err := sc.SyscallConn()
			if err != nil {
				return 0, err
			}
			rc = sys
		} else {
			return 0, fmt.Errorf("peer pid: unsupported conn %T", c)
		}
	}
	var (
		ucred *syscall.Ucred
		opErr error
	)
	err := rc.Control(func(fd uintptr) {
		ucred, opErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		return 0, opErr
	}
	if ucred == nil {
		return 0, fmt.Errorf("peer pid: nil ucred")
	}
	return int(ucred.Pid), nil
}
