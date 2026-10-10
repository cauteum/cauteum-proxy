// Package proxy implements mandatory egress (CONNECT + HTTP L7 + TLS terminate).
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cauteum-haven/cauteum-core"
	"github.com/cauteum-haven/cauteum-core/engine"
	"github.com/cauteum-haven/cauteum-core/policy"
	"github.com/cauteum-haven/cauteum-proxy/proxy/middleware"
	"github.com/cauteum-haven/slogx"
)

// EgressProxy applies policy and serves egress for a sandbox network.
type EgressProxy interface {
	Apply(ctx context.Context, doc policy.Document) error
	Close(ctx context.Context) error
}

// PolicyStatusReporter reports the revision applied by the proxy to the
// gateway. Implementations must authenticate as the owning sandbox.
type PolicyStatusReporter func(ctx context.Context, revision uint32, loadError string) error

// Server is a default-deny HTTP proxy (CONNECT + absolute-form HTTP) backed by engine.PolicyEngine.
type Server struct {
	mu                 sync.RWMutex
	auditMu            sync.Mutex
	eng                engine.PolicyEngine
	doc                policy.Document
	policyGen          int
	audit              io.Writer
	server             *http.Server
	activeTunnels      map[net.Conn]struct{}
	ca                 *MitmCA
	secrets            SecretStore
	tokenGrants        map[string]TokenGrantCredential
	tokenGrantResolver TokenGrantResolver
	Middleware         *middleware.Pipeline
	log                *slog.Logger
	allowLoopback      bool // test-only: SSRF permits 127.0.0.0/8 + ::1. See NewServerForTests.
	// UpstreamTLS overrides the TLS client config used when dialing real backends after terminate.
	// Tests may set InsecureSkipVerify; production leaves this nil (system roots).
	UpstreamTLS *tls.Config
	configErr   error
	// GatewayToken is the sandbox-scoped supervisor bearer for gateway calls
	// (proposals). Never exposed to placeholder resolution.
	GatewayToken string
	// ReportPolicyStatus acknowledges policy application to the gateway. A nil
	// reporter keeps standalone/debug proxy operation independent of a gateway.
	ReportPolicyStatus PolicyStatusReporter

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
	log := slog.Default().With(slog.String("component", "egress-proxy"))
	ca, err := GenerateMitmCA()
	if err != nil {
		// Still usable for L4 / plaintext; terminate will fail closed.
		log.Warn("MITM CA generation failed; HTTPS interception is unavailable", slogx.Err(err))
		ca = nil
	}
	srv := &Server{
		eng: eng, audit: audit, ca: ca,
		log:         log,
		secrets:     LoadSecretsFromEnviron(os.Environ()),
		tokenGrants: loadTokenGrantsFromEnviron(os.Environ()),
		Middleware:  middleware.FromEnviron(os.Environ()),
		proposals:   map[string]*localProposal{},
	}
	if len(srv.tokenGrants) > 0 {
		srv.tokenGrantResolver = NewSPIFFETokenGrantResolver()
	}
	if caPath := strings.TrimSpace(os.Getenv("CAUTEUM_EGRESS_CA_BUNDLE")); caPath != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			srv.configErr = fmt.Errorf("system certificate roots are unavailable")
		} else {
			body, readErr := os.ReadFile(caPath)
			if readErr != nil {
				srv.configErr = fmt.Errorf("read configured egress CA bundle")
			} else if len(body) > 1<<20 {
				srv.configErr = fmt.Errorf("configured egress CA bundle exceeds 1 MiB")
			} else if err := appendEgressCerts(roots, body); err != nil {
				srv.configErr = fmt.Errorf("configured egress CA bundle is invalid: %w", err)
			} else {
				srv.UpstreamTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
			}
		}
	}
	return srv
}

func appendEgressCerts(roots *x509.CertPool, bundle []byte) error {
	remaining := bytes.TrimSpace(bundle)
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("invalid certificate PEM block")
		}
		certificates, err := x509.ParseCertificates(block.Bytes)
		if err != nil || len(certificates) == 0 {
			return fmt.Errorf("invalid certificate in PEM bundle")
		}
		for _, certificate := range certificates {
			roots.AddCert(certificate)
			count++
		}
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return fmt.Errorf("PEM bundle contains no certificates")
	}
	return nil
}

func (s *Server) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}
	return slog.Default()
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
	s.logger().Info("proxy policy applied", slog.String("op", "proxy.policy.apply"), slog.Int("generation", s.policyGen))
	for conn := range s.activeTunnels {
		_ = conn.Close()
		delete(s.activeTunnels, conn)
	}
	for _, warning := range doc.TLSWarnings() {
		s.logAudit(auditEvent{Action: "audit", Reason: warning, Allow: true})
	}
	return nil
}

// trackTunnel binds an established stream to the policy generation that
// authorized it. A concurrent update invalidates stale decisions.
func (s *Server) trackTunnel(conn net.Conn, generation int) (func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policyGen != generation {
		return nil, false
	}
	if s.activeTunnels == nil {
		s.activeTunnels = make(map[net.Conn]struct{})
	}
	s.activeTunnels[conn] = struct{}{}
	return func() {
		s.mu.Lock()
		delete(s.activeTunnels, conn)
		s.mu.Unlock()
	}, true
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
	if s.configErr != nil {
		return fmt.Errorf("proxy configuration: %w", s.configErr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger().Error("proxy listener bind failed", slog.String("op", "proxy.serve"), slog.String("addr", addr), slogx.Err(err))
		return fmt.Errorf("proxy listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.configErr != nil {
		_ = ln.Close()
		return fmt.Errorf("proxy configuration: %w", s.configErr)
	}
	log := s.logger().With(slog.String("op", "proxy.serve"), slog.String("addr", ln.Addr().String()))
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: headerReadTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return withConn(ctx, c)
		},
	}
	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()
	log.Info("proxy listener started")
	defer log.Info("proxy listener stopped")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		log.Debug("proxy shutdown requested")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Warn("proxy graceful shutdown failed", slogx.Err(err))
		}
		err := <-errCh
		if err == http.ErrServerClosed {
			return ctx.Err()
		}
		if err != nil {
			log.Error("proxy server failed during shutdown", slogx.Err(err))
		}
		return err
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		if err != nil {
			log.Error("proxy server failed", slogx.Err(err))
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
	pathOnly = r.URL.EscapedPath()
	if pathOnly == "" {
		pathOnly = "/"
	}
	if !dec.Allow {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cauteum-proxy: denied\n"))
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

	if err := s.runMiddleware(r.Context(), r, "http", host, port, pathOnly); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cauteum-proxy: middleware denied\n"))
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
	secrets, err = s.resolveTokenGrantPlaceholders(r.Context(), host, port, pathOnly, r, bound, secrets)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cauteum-proxy: token grant failed\n"))
		s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "token grant failed", Allow: false, Method: r.Method, Path: pathOnly, Binary: bin})
		return
	}
	rewSecrets, err := SecretsForEndpoint(secrets, bound, used)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cauteum-proxy: credential_endpoint_mismatch\n"))
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
	rewriteBody := dec.Matched != nil && dec.Matched.Rule.Protocol == "rest" && dec.Matched.Rule.RequestBodyCredentialRewrite
	if err := RewriteHTTPRequestWithOptions(r, rewSecrets, rewriteBody); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cauteum-proxy: credential rewrite failed\n"))
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
	if err := s.runMiddlewareResponse(r.Context(), r, host, port, pathOnly, resp); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cauteum-proxy: response middleware denied\n"))
		return
	}
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

const maxBufferedMiddlewareResponse = 64 << 20

func (s *Server) runMiddlewareResponse(ctx context.Context, request *http.Request, host string, port int, pathOnly string, resp *http.Response) error {
	s.mu.RLock()
	pipe := s.Middleware
	s.mu.RUnlock()
	if pipe == nil || !pipe.HasResponseStages() {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBufferedMiddlewareResponse+1))
	_ = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read response for middleware: %w", err)
	}
	if len(body) > maxBufferedMiddlewareResponse {
		return fmt.Errorf("response exceeds middleware buffer")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	reqHeaders := map[string]string{}
	for name, values := range request.Header {
		if len(values) > 0 {
			reqHeaders[name] = values[0]
		}
	}
	response := &middleware.Response{StatusCode: resp.StatusCode, Headers: resp.Header, Trailers: resp.Trailer, Body: body}
	err = pipe.RunResponse(ctx, middleware.Request{Scheme: "http", Host: host, Port: port, Method: request.Method, Path: pathOnly, Headers: reqHeaders}, response)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(response.Body))
	resp.ContentLength = int64(len(response.Body))
	resp.Header = response.Headers
	resp.Trailer = response.Trailers
	resp.Header.Set("Content-Length", strconv.Itoa(len(response.Body)))
	return nil
}

func (s *Server) runMiddleware(ctx context.Context, r *http.Request, scheme, host string, port int, pathOnly string) error {
	s.mu.RLock()
	pipe := s.Middleware
	s.mu.RUnlock()
	if pipe == nil || len(pipe.Stages) == 0 {
		return nil
	}
	body, err := middlewareRequestBody(r)
	if err != nil {
		return err
	}
	h := map[string]string{}
	for k, vv := range r.Header {
		if len(vv) > 0 {
			h[k] = vv[0]
		}
	}
	dec, err := pipe.Run(ctx, middleware.Request{
		Scheme: scheme, Host: host, Port: port, Method: r.Method, Path: pathOnly, Headers: h, Body: body,
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
	handledHeaders := map[string]struct{}{}
	for _, mutation := range dec.HeaderMutations {
		handledHeaders[mutation.Name] = struct{}{}
	}
	for k, v := range dec.MutateHeaders {
		if _, handled := handledHeaders[k]; !handled {
			r.Header.Set(k, v)
		}
	}
	for _, mutation := range dec.HeaderMutations {
		if mutation.Remove {
			r.Header.Del(mutation.Name)
		} else if mutation.Append {
			r.Header.Add(mutation.Name, mutation.Value)
		} else if !mutation.Skip || r.Header.Get(mutation.Name) == "" {
			r.Header.Set(mutation.Name, mutation.Value)
		}
	}
	for _, name := range dec.RemoveHeaders {
		r.Header.Del(name)
	}
	if dec.HasBody {
		r.Body = io.NopCloser(bytes.NewReader(dec.Body))
		r.ContentLength = int64(len(dec.Body))
	}
	return nil
}

const maxMiddlewareRequestBody = 4 << 20

func middlewareRequestBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMiddlewareRequestBody+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read middleware request body: %w", err)
	}
	if len(body) > maxMiddlewareRequestBody {
		return nil, fmt.Errorf("middleware request body exceeds %d bytes", maxMiddlewareRequestBody)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return body, nil
}

func (s *Server) decideHTTP(r *http.Request, eng engine.PolicyEngine, host string, port int, pathOnly, binary string) (engine.Decision, error) {
	l4, err := eng.Decide(r.Context(), engine.EgressRequest{Host: host, Port: port, Binary: binary})
	if err != nil {
		return engine.Decision{}, err
	}
	if !l4.Allow {
		return l4, nil
	}
	if l4.Matched != nil && blocksUninspectedCredentials(l4.Matched.Rule) {
		return engine.Decision{
			Allow: false, Reason: "credentialed endpoint requires L7 inspection; set allow_uninspected_credentials: true to opt in",
			Matched: l4.Matched,
		}, nil
	}
	if l4.Matched != nil && l4.Matched.Rule.NeedsL7() {
		if r.URL.Fragment != "" || strings.Contains(r.RequestURI, "#") {
			return engine.Decision{Allow: false, Reason: "http path: request target contains a fragment", Matched: l4.Matched}, nil
		}
		canonical, err := canonicalizeL7Path(requestTargetPath(r, pathOnly), l4.Matched.Rule.AllowEncodedSlash)
		if err != nil {
			return engine.Decision{Allow: false, Reason: "http path: " + err.Error(), Matched: l4.Matched}, nil
		}
		decoded, err := url.PathUnescape(canonical)
		if err != nil {
			return engine.Decision{}, fmt.Errorf("canonical path: %w", err)
		}
		r.URL.Path = decoded
		r.URL.RawPath = canonical
		pathOnly = canonical
	}
	var query map[string][]string
	if l4.Matched != nil && l4.Matched.Rule.NeedsL7() {
		query, err = parsePolicyQuery(r.URL.RawQuery)
		if err != nil {
			return engine.Decision{Allow: false, Reason: "http query: " + err.Error(), Matched: l4.Matched}, nil
		}
	}
	if l4.Matched != nil && isMCPRule(&l4.Matched.Rule) {
		mcpConfig := l4.Matched.Rule.MCP
		if mcpConfig == nil && l4.Matched.Rule.JSONRPC != nil && l4.Matched.Rule.JSONRPC.MaxBodyBytes != nil {
			mcpConfig = &policy.MCPConfig{MaxBodyBytes: *l4.Matched.Rule.JSONRPC.MaxBodyBytes}
		}
		messages, err := parseMCPMessages(r, mcpConfig)
		if err != nil {
			return engine.Decision{Allow: false, Reason: err.Error(), Matched: l4.Matched}, nil
		}
		var audit bool
		for _, message := range messages {
			if message.response || message.receiveStream {
				continue // MCP permits client responses to server-initiated requests.
			}
			decision, err := eng.DecideHTTP(r.Context(), engine.HTTPRequest{
				Query: query,
				Host:  host, Port: port, Method: message.method, Path: mcpDecidePath(pathOnly, message.tool), Binary: binary,
			})
			if err != nil || !decision.Allow {
				return decision, err
			}
			audit = audit || decision.Audit
		}
		return engine.Decision{Allow: true, Audit: audit, Reason: "all MCP messages allowed", Matched: l4.Matched}, nil
	}
	if l4.Matched != nil && strings.EqualFold(strings.TrimSpace(l4.Matched.Rule.Protocol), policy.ProtocolJSONRPC) {
		methods, err := parseJSONRPCRequest(r, l4.Matched.Rule.JSONRPC)
		if err != nil {
			return engine.Decision{Allow: false, Reason: err.Error(), Matched: l4.Matched}, nil
		}
		var audit bool
		for _, method := range methods {
			decision, err := eng.DecideHTTP(r.Context(), engine.HTTPRequest{
				Query: query,
				Host:  host, Port: port, Method: method, Path: pathOnly, Binary: binary,
			})
			if err != nil || !decision.Allow {
				return decision, err
			}
			audit = audit || decision.Audit
		}
		return engine.Decision{Allow: true, Audit: audit, Reason: "all JSON-RPC methods allowed", Matched: l4.Matched}, nil
	}
	if l4.Matched != nil && strings.EqualFold(strings.TrimSpace(l4.Matched.Rule.Protocol), policy.ProtocolGraphQL) {
		operations, err := parseGraphQLRequest(r, l4.Matched.Rule)
		if err != nil {
			return engine.Decision{Allow: false, Reason: err.Error(), Matched: l4.Matched}, nil
		}
		var audit bool
		for _, operation := range operations {
			decision, err := eng.DecideHTTP(r.Context(), engine.HTTPRequest{
				Query: query,
				Host:  host, Port: port, Method: r.Method, Path: pathOnly, Binary: binary, GraphQL: &operation,
			})
			if err != nil || !decision.Allow {
				return decision, err
			}
			audit = audit || decision.Audit
		}
		return engine.Decision{Allow: true, Audit: audit, Reason: "all GraphQL operations allowed", Matched: l4.Matched}, nil
	}
	return eng.DecideHTTP(r.Context(), engine.HTTPRequest{
		Query: query,
		Host:  host, Port: port, Method: r.Method, Path: pathOnly, Binary: binary,
	})
}

func blocksUninspectedCredentials(rule policy.AllowRule) bool {
	return len(rule.CredentialKeys) > 0 && !rule.NeedsL7() && !rule.AllowUninspectedCredentials
}

// CONNECT is kept as a thin Apply-only adapter for sandbox.Manager.
type CONNECT struct {
	*Server
}

// NewCONNECT wraps an engine in a Server-backed EgressProxy.
func NewCONNECT(eng engine.PolicyEngine) *CONNECT {
	return &CONNECT{Server: NewServer(eng, nil)}
}
