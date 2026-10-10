package proxy

import (
	"io"

	"github.com/cautem/cautem-core/engine"
)

// NewServerForTests enables loopback only in test binaries.
func NewServerForTests(eng engine.PolicyEngine, audit io.Writer) *Server {
	s := NewServer(eng, audit)
	s.allowLoopback = true
	return s
}
