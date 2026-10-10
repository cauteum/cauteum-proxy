// Package service declares proxy use-case ports at the consumption site.
package service

import (
	"context"

	"github.com/cautem/cauteum-core/policy"
)

// PolicySource loads the active egress policy document.
type PolicySource interface {
	Load(ctx context.Context) (*policy.Document, error)
	Watch(ctx context.Context) (<-chan *policy.Document, error)
}

// Decider evaluates whether a flow is allowed.
type Decider interface {
	Allow(ctx context.Context, host string, port int) (bool, string, error)
}
