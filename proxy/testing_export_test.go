package proxy

import (
	"io"

	"github.com/cauteum/cauteum-core/engine"
)

// NewServerForTests enables loopback only in test binaries.
func NewServerForTests(eng engine.PolicyEngine, audit io.Writer) *Server {
	s := NewServer(eng, audit)
	s.allowLoopback = true
	return s
}
