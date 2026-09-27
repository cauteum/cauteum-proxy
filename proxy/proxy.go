// Package proxy implements mandatory egress (CONNECT + HTTP L7 + TLS terminate).
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/whaleshell/whaleshell-core"
	"github.com/whaleshell/whaleshell-core/engine"
	"github.com/whaleshell/whaleshell-core/policy"
	"github.com/whaleshell/whaleshell-proxy/proxy/middleware"
)

// EgressProxy applies policy and serves egress for a sandbox network.
type EgressProxy interface {
	Apply(ctx context.Context, doc policy.Document) error
	Close(ctx context.Context) error
}

// Server is a default-deny HTTP proxy (CONNECT + absolute-form HTTP) backed by engine.PolicyEngine.
type Server struct {
	mu            sync.RWMutex
	eng           engine.PolicyEngine
	doc           policy.Document
	policyGen     int
	audit         io.Writer
	server        *http.Server
	ca            *MitmCA
	secrets       SecretStore
	Middleware    *middleware.Pipeline
	allowLoopback bool // test-only: SSRF permits 127.0.0.0/8 + ::1. See NewServerForTests.
	// UpstreamTLS overrides the TLS client config used when dialing real backends after terminate.
	// Tests may set InsecureSkipVerify; production leaves this nil (system roots).
	UpstreamTLS *tls.Config
	// GatewayToken is the sandbox-scoped supervisor bearer for gateway calls
	// (proposals). Never exposed to placeholder resolution.
	GatewayToken string

	denials   []denialLine
	proposals map[string]*localProposal
}

// NewServer builds a CONNECT/HTTP proxy with an ephemeral MITM CA. audit defaults to stderr.
func NewServer(eng engine.PolicyEngine, audit io.Writer) *Server {
	if eng == nil {
		eng = &engine.Allowlist{}
	}
	if audit == nil {
		audit = os.Stderr
	}
	ca, err := GenerateMitmCA()
	if err != nil {
		// Still usable for L4 / plaintext; terminate will fail closed.
		ca = nil
	}
	return &Server{
		eng: eng, audit: audit, ca: ca,
		secrets:    LoadSecretsFromEnviron(os.Environ()),
		Middleware: middleware.FromEnviron(os.Environ()),
		proposals:  map[string]*localProposal{},
	}
}

// SetSecrets replaces the credential placeholder resolution map.
func (s *Server) SetSecrets(secrets SecretStore) {
	s.mu.Lock()
	s.secrets = secrets
	s.mu.Unlock()
}

// Apply reloads policy (hot-reload safe).
func (s *Server) Apply(_ context.Context, doc policy.Document) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eng == nil {
		return fmt.Errorf("proxy: %w", core.ErrNotImplemented)
	}
	if err := s.eng.Apply(doc); err != nil {
		return err
	}
	s.doc = doc
	s.policyGen++
	return nil
}

// CurrentDocument returns the last successfully applied policy (copy).
func (s *Server) CurrentDocument() policy.Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.doc
}

// Close shuts down the HTTP server if Serve was used.
func (s *Server) Close(ctx context.Context) error {
	s.mu.RLock()
	srv := s.server
	s.mu.RUnlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// Handler returns the HTTP handler (CONNECT + absolute-form + /healthz + /ca.pem).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

// ListenAndServe listens on addr until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return withConn(ctx, c)
		},
	}
	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		err := <-errCh
		if err == http.ErrServerClosed {
			return ctx.Err()
		}
		return err
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Host == "" {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		case "/ca.pem":
			s.mu.RLock()
			ca := s.ca
			s.mu.RUnlock()
			if ca == nil {
				http.Error(w, "ca unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ca.CertPEM())
			return
		}
	}

	if r.Method == http.MethodConnect {
		s.handleCONNECT(w, r)
		return
	}
	if r.URL.IsAbs() || r.URL.Scheme != "" {
		s.handleAbsoluteHTTP(w, r)
		return
	}
	http.Error(w, "CONNECT or absolute-form HTTP only", http.StatusMethodNotAllowed)
	s.logAudit(auditEvent{Action: "reject", Host: r.Host, Reason: "method " + r.Method, Allow: false})
}

func (s *Server) handleAbsoluteHTTP(w http.ResponseWriter, r *http.Request) {
	u := r.URL
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Scheme != "http" {
		http.Error(w, "absolute-form HTTPS not supported; use CONNECT", http.StatusBadRequest)
		return
	}
	host := u.Hostname()
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}
	portStr := u.Port()
	if portStr == "" {
		portStr = "80"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(w, "bad port", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	eng := s.eng
	allowLoop := s.allowLoopback
	secrets := s.secrets
	s.mu.RUnlock()
	if eng == nil {
		http.Error(w, "proxy not configured", http.StatusServiceUnavailable)
		return
	}

	pathOnly := u.EscapedPath()
	if pathOnly == "" {
		pathOnly = "/"
	}

	bin := callerBinary(r)
	dec, err := s.decideHTTP(r, eng, host, port, pathOnly, bin)
	if err != nil {
		http.Error(w, "policy error", http.StatusInternalServerError)
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: err.Error(), Allow: false, Binary: bin})
		return
	}
	if !dec.Allow {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("whaleshell-proxy: denied\n"))
		s.logAudit(auditEvent{
			Action: "deny", Host: host, Port: port, Reason: dec.Reason, Allow: false,
			Method: r.Method, Path: pathOnly, Binary: bin,
		})
		return
	}
	if dec.Audit {
		s.logAudit(auditEvent{
			Action: "audit", Host: host, Port: port, Reason: dec.Reason, Allow: true,
			Method: r.Method, Path: pathOnly, Binary: bin,
		})
	}

	if err := s.runMiddleware(r.Context(), host, port, r.Method, pathOnly, r.Header); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("whaleshell-proxy: middleware denied\n"))
		s.logAudit(auditEvent{
			Action: "deny", Host: host, Port: port, Reason: err.Error(), Allow: false,
			Method: r.Method, Path: pathOnly, Binary: bin,
		})
		return
	}

	bound := []string(nil)
	if dec.Matched != nil {
		bound = dec.Matched.Rule.CredentialKeys
	}
	used := PlaceholderKeysInRequest(r)
	rewSecrets, err := SecretsForEndpoint(secrets, bound, used)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("whaleshell-proxy: credential_endpoint_mismatch\n"))
		s.logAudit(auditEvent{
			Action: "deny", Host: host, Port: port, Reason: err.Error(), Allow: false,
			Method: r.Method, Path: pathOnly, Binary: bin,
		})
		s.logAudit(auditEvent{
			Action: "finding", Host: host, Port: port, Reason: "credential_endpoint_mismatch", Allow: false,
			Method: r.Method, Path: pathOnly, Binary: bin,
		})
		return
	}
	if err := RewriteHTTPRequest(r, rewSecrets); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("whaleshell-proxy: credential rewrite failed\n"))
		s.logAudit(auditEvent{
			Action: "deny", Host: host, Port: port, Reason: "credential rewrite: " + err.Error(), Allow: false,
			Method: r.Method, Path: pathOnly, Binary: bin,
		})
		return
	}

	var allowedIPs []string
	if dec.Matched != nil {
		allowedIPs = dec.Matched.AllowedIPs
	}
	backend, err := DialSSRF(r.Context(), host, portStr, SSRFOptions{AllowedIPs: allowedIPs, allowLoopback: allowLoop})
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		s.logAudit(auditEvent{Action: "dial_error", Host: host, Port: port, Reason: err.Error(), Allow: true})
		return
	}
	defer backend.Close()

	outReq := &http.Request{
		Method: r.Method,
		URL: &url.URL{
			Scheme:   "http",
			Host:     net.JoinHostPort(host, portStr),
			Path:     u.Path,
			RawPath:  u.RawPath,
			RawQuery: u.RawQuery,
		},
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        r.Header.Clone(),
		Body:          r.Body,
		Host:          host,
		ContentLength: r.ContentLength,
	}
	if portStr != "80" {
		outReq.Host = net.JoinHostPort(host, portStr)
	}
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	if err := outReq.Write(backend); err != nil {
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}
	br := bufio.NewReader(backend)
	resp, err := http.ReadResponse(br, outReq)
	if err != nil {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		s.logAudit(auditEvent{Action: "dial_error", Host: host, Port: port, Reason: err.Error(), Allow: true})
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	s.logAudit(auditEvent{
		Action: "allow", Host: host, Port: port, Reason: dec.Reason, Allow: true,
		Method: r.Method, Path: pathOnly,
	})
}

func (s *Server) runMiddleware(ctx context.Context, host string, port int, method, pathOnly string, hdr http.Header) error {
	s.mu.RLock()
	pipe := s.Middleware
	s.mu.RUnlock()
	if pipe == nil || len(pipe.Stages) == 0 {
		return nil
	}
	h := map[string]string{}
	for k, vv := range hdr {
		if len(vv) > 0 {
			h[k] = vv[0]
		}
	}
	dec, err := pipe.Run(ctx, middleware.Request{
		Host: host, Port: port, Method: method, Path: pathOnly, Headers: h,
	})
	if err != nil {
		return err
	}
	if !dec.Allow {
		if dec.Reason == "" {
			return fmt.Errorf("middleware denied")
		}
		return fmt.Errorf("%s", dec.Reason)
	}
	for k, v := range dec.MutateHeaders {
		hdr.Set(k, v)
	}
	return nil
}

func (s *Server) decideHTTP(r *http.Request, eng engine.PolicyEngine, host string, port int, pathOnly, binary string) (engine.Decision, error) {
	l4, err := eng.Decide(r.Context(), engine.EgressRequest{Host: host, Port: port, Binary: binary})
	if err != nil {
		return engine.Decision{}, err
	}
	if !l4.Allow {
		return l4, nil
	}
	if l4.Matched != nil && isMCPRule(&l4.Matched.Rule) {
		method, tool, err := parseMCPRequest(r)
		if err != nil {
			return engine.Decision{Allow: false, Reason: err.Error(), Matched: l4.Matched}, nil
		}
		return eng.DecideHTTP(r.Context(), engine.HTTPRequest{
			Host: host, Port: port, Method: method, Path: mcpDecidePath(pathOnly, tool), Binary: binary,
		})
	}
	return eng.DecideHTTP(r.Context(), engine.HTTPRequest{
		Host: host, Port: port, Method: r.Method, Path: pathOnly, Binary: binary,
	})
}

// CONNECT is kept as a thin Apply-only adapter for sandbox.Manager.
type CONNECT struct {
	*Server
}

// NewCONNECT wraps an engine in a Server-backed EgressProxy.
func NewCONNECT(eng engine.PolicyEngine) *CONNECT {
	return &CONNECT{Server: NewServer(eng, nil)}
}
