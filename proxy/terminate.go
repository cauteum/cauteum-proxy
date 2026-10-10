package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cauteum-haven/cauteum-core/engine"
	"github.com/cauteum-haven/cauteum-core/policy"
	"github.com/cauteum-haven/cauteum-proxy/proxy/middleware"
)

const maxRawTunnelLifetime = 30 * time.Minute

func (s *Server) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		http.Error(w, "bad port", http.StatusBadRequest)
		s.logAudit(auditEvent{Action: "reject", Host: r.Host, Reason: "bad port", Allow: false})
		return
	}

	s.mu.RLock()
	eng := s.eng
	allowLoop := s.allowLoopback
	ca := s.ca
	policyGen := s.policyGen
	s.mu.RUnlock()
	if eng == nil {
		http.Error(w, "proxy not configured", http.StatusServiceUnavailable)
		return
	}
	bin := callerBinary(r)
	// inference.local / policy.local are managed sandbox-local adapters.
	if s.isInferenceLocal(host) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, "hijack failed", http.StatusInternalServerError)
			return
		}
		defer client.Close()
		s.handleInferenceLocal(w, r, client)
		return
	}
	if s.isPolicyLocal(host) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, "hijack failed", http.StatusInternalServerError)
			return
		}
		defer client.Close()
		s.handlePolicyLocal(w, r, client)
		return
	}
	dec, err := eng.Decide(r.Context(), engine.EgressRequest{Host: host, Port: port, Binary: bin})
	if err != nil {
		http.Error(w, "policy error", http.StatusInternalServerError)
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: err.Error(), Allow: false, Binary: bin})
		return
	}
	if !dec.Allow {
		body := DenyBodyJSON(host, port, dec.Reason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(body)
		s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: dec.Reason, Allow: false, Binary: bin})
		return
	}
	if dec.Audit {
		s.logAudit(auditEvent{Action: "audit", Host: host, Port: port, Reason: dec.Reason, Allow: true, Binary: bin})
	}

	var allowedIPs []string
	if dec.Matched != nil {
		allowedIPs = dec.Matched.AllowedIPs
	}

	needsL7 := dec.Matched != nil && dec.Matched.Rule.NeedsL7()
	credentialed := dec.Matched != nil && blocksUninspectedCredentials(dec.Matched.Rule)
	tlsMode := ""
	if dec.Matched != nil {
		tlsMode = strings.ToLower(strings.TrimSpace(dec.Matched.Rule.TLS))
	}
	if credentialed {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cauteum-proxy: credentialed endpoint requires L7 inspection\n"))
		s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "credentialed endpoint requires L7 inspection", Allow: false, Binary: bin})
		return
	}

	backend, err := DialSSRF(r.Context(), host, portStr, SSRFOptions{AllowedIPs: allowedIPs, allowLoopback: allowLoop})
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		s.logAudit(auditEvent{Action: "dial_error", Host: host, Port: port, Reason: err.Error(), Allow: true})
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = backend.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		_ = backend.Close()
		return
	}
	releaseTunnel, current := s.trackTunnel(clientConn, policyGen)
	if !current {
		_ = backend.Close()
		_ = clientConn.Close()
		return
	}
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()

	if needsL7 && tlsMode != "skip" {
		if ca == nil {
			_ = backend.Close()
			_ = clientConn.Close()
			releaseTunnel()
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "mitm ca missing", Allow: false})
			return
		}
		reason := dec.Reason + " tls:auto"
		if tlsMode == policy.TLSTerminate {
			reason += "; 'tls: terminate' is deprecated; TLS termination is now automatic"
		}
		if tlsMode == policy.TLSPassthrough {
			reason += "; 'tls: passthrough' is deprecated; TLS termination is now automatic"
		}
		s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: reason, Allow: true, Binary: bin})
		go func() { defer releaseTunnel(); s.mitmHTTPS(clientConn, bufrw.Reader, backend, host, port, eng, bin) }()
		return
	}
	protocol := ""
	if dec.Matched != nil {
		protocol = strings.ToLower(strings.TrimSpace(dec.Matched.Rule.Protocol))
	}
	// OpenShell v1 has no SQL parser/relay. SQL audit policies pass database
	// TLS bytes through untouched; classifying them as HTTPS would corrupt SQL.
	if !needsL7 && tlsMode != "skip" && protocol != policy.ProtocolSQL {
		tlsPayload, err := tunnelStartsTLS(clientConn, bufrw.Reader)
		if err != nil {
			_ = backend.Close()
			_ = clientConn.Close()
			releaseTunnel()
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS auto-detection: " + err.Error(), Allow: false, Binary: bin})
			return
		}
		if tlsPayload {
			if ca == nil {
				_ = backend.Close()
				_ = clientConn.Close()
				releaseTunnel()
				s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS auto-detection requires MITM CA", Allow: false, Binary: bin})
				return
			}
			s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: dec.Reason + " tls:auto-detected", Allow: true, Binary: bin})
			go func() { defer releaseTunnel(); s.mitmHTTPS(clientConn, bufrw.Reader, backend, host, port, eng, bin) }()
			return
		}
	}

	allowReason := dec.Reason
	if needsL7 && tlsMode == "skip" {
		allowReason += " tls:skip (L7 bypass)"
	}
	s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: allowReason, Allow: true, Binary: bin})
	// Drain any buffered bytes into the tunnel.
	deadline := time.AfterFunc(maxRawTunnelLifetime, func() { _ = clientConn.Close() })
	go func() {
		defer deadline.Stop()
		defer releaseTunnel()
		tunnelWithBuf(backend, clientConn, bufrw.Reader)
	}()
}

// tunnelStartsTLS performs the same narrow TLS record-prefix check used by
// OpenShell's CONNECT classifier. The read deadline bounds how long a client
// without payload bytes can hold an established CONNECT open before raw relay.
func tunnelStartsTLS(conn net.Conn, reader *bufio.Reader) (bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return false, err
	}
	prefix, _ := reader.Peek(2)
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return false, err
	}
	return len(prefix) >= 2 && prefix[0] == 0x16 && prefix[1] == 0x03, nil
}

func (s *Server) mitmHTTPS(client net.Conn, clientBuf *bufio.Reader, backend net.Conn, host string, port int, eng engine.PolicyEngine, binary string) {
	defer client.Close()
	defer backend.Close()

	s.mu.RLock()
	ca := s.ca
	upTLSCfg := ClientTLSConfig(host)
	if s.UpstreamTLS != nil {
		upTLSCfg = s.UpstreamTLS.Clone()
		if upTLSCfg.ServerName == "" {
			upTLSCfg.ServerName = host
		}
		if len(upTLSCfg.NextProtos) == 0 {
			upTLSCfg.NextProtos = []string{"http/1.1"}
		}
	}
	s.mu.RUnlock()
	if ca == nil {
		return
	}
	tlsCfg, err := ca.ServerTLSConfig(host)
	if err != nil {
		return
	}
	clientTLS := tls.Server(&bufConn{Conn: client, r: clientBuf}, tlsCfg)
	if err := clientTLS.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}
	if err := clientTLS.Handshake(); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "client tls: " + err.Error(), Allow: false})
		return
	}
	if err := clientTLS.SetDeadline(time.Time{}); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}

	upTLS := tls.Client(backend, upTLSCfg)
	if err := upTLS.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}
	if err := upTLS.Handshake(); err != nil {
		s.logAudit(auditEvent{Action: "dial_error", Host: host, Port: port, Reason: "upstream tls: " + err.Error(), Allow: true})
		return
	}
	if err := upTLS.SetDeadline(time.Time{}); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}

	clientBR := bufio.NewReader(clientTLS)
	upBR := bufio.NewReader(upTLS)

	s.mu.RLock()
	secrets := s.secrets
	s.mu.RUnlock()

	for {
		if err := clientTLS.SetReadDeadline(time.Now().Add(upstreamIdleTimeout)); err != nil {
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
			return
		}
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			return
		}
		pathOnly := req.URL.EscapedPath()
		if pathOnly == "" {
			pathOnly = "/"
		}
		dec, err := s.decideHTTP(req, eng, host, port, pathOnly, binary)
		pathOnly = req.URL.EscapedPath()
		if pathOnly == "" {
			pathOnly = "/"
		}
		if err != nil || !dec.Allow {
			var reason string
			if err == nil {
				reason = dec.Reason
			} else {
				reason = err.Error()
			}
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: reason, Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("cauteum-proxy: denied\n")),
			}
			resp.Header.Set("Content-Type", "text/plain")
			resp.Header.Set("Connection", "close")
			resp.ContentLength = int64(len("cauteum-proxy: denied\n"))
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}
		if dec.Audit {
			s.logAudit(auditEvent{
				Action: "audit", Host: host, Port: port, Reason: dec.Reason, Allow: true,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
		}

		if err := s.runMiddleware(req.Context(), req, "https", host, port, pathOnly); err != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: err.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "cauteum-proxy: middleware denied\n"
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader(msg)),
			}
			resp.Header.Set("Content-Type", "text/plain")
			resp.Header.Set("Connection", "close")
			resp.ContentLength = int64(len(msg))
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}

		bound := []string(nil)
		if dec.Matched != nil {
			bound = dec.Matched.Rule.CredentialKeys
		}
		used := PlaceholderKeysInRequest(req)
		secrets, bindErr := s.resolveTokenGrantPlaceholders(req.Context(), host, port, pathOnly, req, bound, secrets)
		if bindErr != nil {
			s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "token grant failed", Allow: false, Method: req.Method, Path: pathOnly, Binary: binary})
			msg := "cauteum-proxy: token grant failed\n"
			resp := &http.Response{StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(msg))}
			resp.Header.Set("Connection", "close")
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}
		rewSecrets, bindErr := SecretsForEndpoint(secrets, bound, used)
		if bindErr != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: bindErr.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			s.logAudit(auditEvent{
				Action: "finding", Host: host, Port: port, Reason: "credential_endpoint_mismatch", Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "cauteum-proxy: credential_endpoint_mismatch\n"
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader(msg)),
			}
			resp.Header.Set("Connection", "close")
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}
		rewriteBody := dec.Matched != nil && dec.Matched.Rule.Protocol == "rest" && dec.Matched.Rule.RequestBodyCredentialRewrite
		if err := RewriteHTTPRequestWithOptions(req, rewSecrets, rewriteBody); err != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: "credential rewrite: " + err.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "cauteum-proxy: credential rewrite failed\n"
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader(msg)),
			}
			resp.Header.Set("Connection", "close")
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}

		outReq := &http.Request{
			Method: req.Method,
			URL: &url.URL{
				Scheme:   "https",
				Host:     net.JoinHostPort(host, strconv.Itoa(port)),
				Path:     req.URL.Path,
				RawPath:  req.URL.RawPath,
				RawQuery: req.URL.RawQuery,
			},
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        req.Header.Clone(),
			Body:          req.Body,
			ContentLength: req.ContentLength,
			Host:          req.Host,
		}
		if outReq.Host == "" {
			outReq.Host = host
		}
		outReq.RequestURI = ""

		wantWS := isWebsocketUpgrade(req)
		var wsSessions []middleware.WebSocketSession
		if wantWS {
			wsSessions, err = s.openWebSocketMiddlewareSessions(req.Context(), req, host, port, pathOnly)
			if err != nil {
				_ = req.Body.Close()
				msg := "cauteum-proxy: websocket middleware denied\n"
				_, _ = clientTLS.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(msg)) + "\r\nConnection: close\r\n\r\n" + msg))
				return
			}
		}
		if err := outReq.Write(upTLS); err != nil {
			_ = req.Body.Close()
			return
		}
		if err := upTLS.SetReadDeadline(time.Now().Add(upstreamIdleTimeout)); err != nil {
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
			return
		}
		resp, err := http.ReadResponse(upBR, outReq)
		if err != nil {
			for _, session := range wsSessions {
				_ = session.Close("upstream failure")
			}
			_ = req.Body.Close()
			return
		}
		if wantWS && resp.StatusCode != http.StatusSwitchingProtocols {
			for _, session := range wsSessions {
				_ = session.Close("upgrade rejected")
			}
		}
		if !wantWS || resp.StatusCode != http.StatusSwitchingProtocols {
			if err := s.runMiddlewareResponse(req.Context(), req, host, port, pathOnly, resp); err != nil {
				_ = resp.Body.Close()
				msg := "cauteum-proxy: response middleware denied\n"
				_, _ = clientTLS.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(msg)) + "\r\nConnection: close\r\n\r\n" + msg))
				return
			}
		}
		s.logAudit(auditEvent{
			Action: "allow", Host: host, Port: port, Reason: dec.Reason, Allow: true,
			Method: req.Method, Path: pathOnly, Binary: binary,
		})
		err = resp.Write(clientTLS)
		_ = resp.Body.Close()
		_ = req.Body.Close()
		if err != nil {
			return
		}
		if wantWS && resp.StatusCode == http.StatusSwitchingProtocols {
			wsRewrite := false
			proto := ""
			bound := []string(nil)
			graphqlOperations := false
			if mr := dec.Matched; mr != nil {
				wsRewrite = mr.Rule.WebsocketCredentialRewrite
				proto = mr.Rule.Protocol
				graphqlOperations = mr.Rule.UsesGraphQLOperationRules()
				bound = mr.Rule.CredentialKeys
			}
			query, err := parsePolicyQuery(req.URL.RawQuery)
			if err != nil {
				s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "websocket query: " + err.Error(), Allow: false, Binary: binary})
				return
			}
			s.relayWebsocket(req.Context(), clientBR, clientTLS, upBR, upTLS, host, port, pathOnly, query, eng, secrets, bound, wsRewrite, proto, graphqlOperations, binary, wsSessions)
			return
		}
		if strings.EqualFold(resp.Header.Get("Connection"), "close") || req.Close || resp.Close {
			return
		}
	}
}

func isWebsocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

func (s *Server) openWebSocketMiddlewareSessions(ctx context.Context, req *http.Request, host string, port int, pathOnly string) ([]middleware.WebSocketSession, error) {
	s.mu.RLock()
	pipe := s.Middleware
	s.mu.RUnlock()
	if pipe == nil {
		return nil, nil
	}
	return pipe.OpenWebSocketSessions(ctx, middleware.WebSocketRequest{SessionID: fmt.Sprintf("%d", time.Now().UnixNano()), Scheme: "wss", Host: host, Port: port, Path: pathOnly, RequestedSubprotocols: websocketSubprotocols(req.Header)})
}

func websocketSubprotocols(headers http.Header) []string {
	var out []string
	for _, value := range headers.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func (s *Server) relayWebsocket(ctx context.Context, clientBR *bufio.Reader, client io.Writer, upBR *bufio.Reader, up io.Writer, host string, port int, pathOnly string, query map[string][]string, eng engine.PolicyEngine, secrets SecretStore, boundKeys []string, rewriteText bool, protocol string, graphqlOperations bool, binary string, wsSessions []middleware.WebSocketSession) {
	for _, session := range wsSessions {
		if err := session.Start(ctx, ""); err != nil {
			_ = session.Close("session start failure")
			return
		}
	}
	defer func() {
		for _, session := range wsSessions {
			_ = session.Close("session ended")
		}
	}()
	var sequence uint64
	var fragments wsFragmentBuffer
	errCh := make(chan struct{}, 2)
	go func() {
		defer func() { errCh <- struct{}{} }()
		for {
			fr, err := readWSFrame(clientBR)
			if err != nil {
				return
			}
			logical, ready, err := fragments.accept(fr)
			if err != nil {
				_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xea}, false)
				return
			}
			if !ready {
				continue
			}
			fr = logical
			switch fr.Opcode {
			case wsOpcodeText:
				sequence++
				for _, session := range wsSessions {
					allow, replacement, err := session.Message(ctx, sequence, fr.Payload, true)
					if err != nil || !allow {
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					fr.Payload = replacement
				}
				method := policy.MethodWebsocketText
				payload := fr.Payload
				var graphqlOperation *policy.GraphQLOperation
				if strings.EqualFold(protocol, policy.ProtocolGraphQL) || graphqlOperations {
					okPass, operation, err := classifyGraphQLWS(payload)
					if err != nil {
						s.logAudit(auditEvent{
							Action: "deny", Host: host, Port: port, Reason: err.Error(), Allow: false,
							Method: "graphql", Path: pathOnly,
						})
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					if okPass {
						if err := writeWSFrame(up, fr.Opcode, payload, false); err != nil {
							return
						}
						continue
					}
					graphqlOperation = operation
				}
				dec, err := eng.DecideHTTP(context.Background(), engine.HTTPRequest{
					Host: host, Port: port, Method: method, Path: pathOnly, Binary: binary, GraphQL: graphqlOperation, Query: query,
				})
				if err != nil || !dec.Allow {
					reason := "websocket text denied"
					if err == nil {
						reason = dec.Reason
					}
					s.logAudit(auditEvent{
						Action: "deny", Host: host, Port: port, Reason: reason, Allow: false,
						Method: method, Path: pathOnly, Binary: binary,
					})
					_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
					return
				}
				if dec.Audit {
					s.logAudit(auditEvent{
						Action: "audit", Host: host, Port: port, Reason: dec.Reason, Allow: true,
						Method: method, Path: pathOnly, Binary: binary,
					})
				}
				if rewriteText && ContainsPlaceholder(string(payload)) {
					used := placeholderKeysInString(string(payload))
					dynamicSecrets, bindErr := s.resolveTokenGrantKeys(ctx, host, port, pathOnly, used, boundKeys, secrets)
					if bindErr != nil {
						s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "token grant failed", Allow: false, Method: method, Path: pathOnly})
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					rew, bindErr := SecretsForEndpoint(dynamicSecrets, boundKeys, used)
					if bindErr != nil {
						s.logAudit(auditEvent{
							Action: "deny", Host: host, Port: port, Reason: bindErr.Error(), Allow: false,
							Method: method, Path: pathOnly,
						})
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					text, err := RewriteText(string(payload), rew)
					if err != nil {
						s.logAudit(auditEvent{
							Action: "deny", Host: host, Port: port, Reason: "ws credential rewrite: " + err.Error(), Allow: false,
							Method: method, Path: pathOnly,
						})
						return
					}
					payload = []byte(text)
				}
				if err := writeWSFrame(up, fr.Opcode, payload, false); err != nil {
					return
				}
			case wsOpcodeBinary:
				sequence++
				for _, session := range wsSessions {
					allow, replacement, err := session.Message(ctx, sequence, fr.Payload, false)
					if err != nil || !allow {
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					fr.Payload = replacement
				}
				if err := writeWSFrame(up, fr.Opcode, fr.Payload, false); err != nil {
					return
				}
			case wsOpcodePing, wsOpcodePong:
				if err := writeWSFrame(up, fr.Opcode, fr.Payload, false); err != nil {
					return
				}
			case wsOpcodeClose:
				_ = writeWSFrame(up, wsOpcodeClose, fr.Payload, false)
				return
			default:
				if err := writeWSFrame(up, fr.Opcode, fr.Payload, false); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer func() { errCh <- struct{}{} }()
		for {
			fr, err := readWSFrame(upBR)
			if err != nil {
				return
			}
			if err := writeWSFrame(client, fr.Opcode, fr.Payload, false); err != nil {
				return
			}
			if fr.Opcode == wsOpcodeClose {
				return
			}
		}
	}()
	<-errCh
}

// classifyGraphQLWS returns control messages separately and extracts the
// operation envelope from GraphQL-over-WebSocket client messages.
func classifyGraphQLWS(payload []byte) (pass bool, operation *policy.GraphQLOperation, err error) {
	var msg struct {
		ID      string          `json:"id"`
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return false, nil, fmt.Errorf("graphql-ws: invalid json")
	}
	switch msg.Type {
	case "connection_init", "ping", "pong", "complete", "stop", "connection_terminate":
		return true, nil, nil
	case "subscribe", "start":
		if strings.TrimSpace(msg.ID) == "" || len(msg.Payload) == 0 || msg.Payload[0] != '{' {
			return false, nil, fmt.Errorf("graphql-ws: operation requires a non-empty id and object payload")
		}
		envelope, err := decodeGraphQLEnvelope(msg.Payload)
		if err != nil {
			return false, nil, err
		}
		operations, err := classifyGraphQLEnvelopes([]graphqlEnvelope{envelope})
		if err != nil || len(operations) != 1 {
			return false, nil, fmt.Errorf("graphql-ws: invalid operation payload")
		}
		return false, &operations[0], nil
	default:
		return false, nil, fmt.Errorf("graphql-ws: unsupported type %q", msg.Type)
	}
}

// bufConn wraps a net.Conn so leftover buffered CONNECT bytes are read first.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	if c.r != nil && c.r.Buffered() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

func tunnelWithBuf(backend, client net.Conn, clientBuf *bufio.Reader) {
	defer backend.Close()
	defer client.Close()
	errCh := make(chan struct{}, 2)
	go func() {
		if clientBuf != nil && clientBuf.Buffered() > 0 {
			_, _ = io.Copy(backend, clientBuf)
		}
		_, _ = io.Copy(backend, client)
		errCh <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, backend)
		errCh <- struct{}{}
	}()
	<-errCh
}

// CA returns the active MITM CA (may be nil until NewServer succeeds).
func (s *Server) CA() *MitmCA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ca
}

// SetCA installs a MITM CA.
func (s *Server) SetCA(ca *MitmCA) {
	s.mu.Lock()
	s.ca = ca
	s.mu.Unlock()
}
