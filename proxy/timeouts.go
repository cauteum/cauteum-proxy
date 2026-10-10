package proxy

import "time"

// Operational defaults for inbound requests, upstream connections, and policy refresh.
const (
	headerReadTimeout            = 10 * time.Second
	shutdownTimeout              = 5 * time.Second
	tlsHandshakeTimeout          = 30 * time.Second
	upstreamIdleTimeout          = 5 * time.Minute
	upstreamDialTimeout          = 15 * time.Second
	proposalRequestTimeout       = 10 * time.Second
	policyPollInterval           = 500 * time.Millisecond
	policyRequestTimeout         = 5 * time.Second
	certificateAuthorityLifetime = 10 * 365 * 24 * time.Hour
)
