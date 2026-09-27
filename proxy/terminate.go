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

	"github.com/whaleshell/whaleshell-core/engine"
	"github.com/whaleshell/whaleshell-core/policy"
)

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
	tlsMode := ""
	if dec.Matched != nil {
		tlsMode = strings.ToLower(strings.TrimSpace(dec.Matched.Rule.TLS))
	}

	if needsL7 && tlsMode != policy.TLSTerminate {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("whaleshell-proxy: L7 over CONNECT requires tls: terminate (or use plaintext absolute-form HTTP)\n"))
		s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "l7 connect without terminate", Allow: false})
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
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()

	if needsL7 && tlsMode == policy.TLSTerminate {
		if ca == nil {
			_ = backend.Close()
			_ = clientConn.Close()
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "mitm ca missing", Allow: false})
			return
		}
		s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: dec.Reason + " tls:terminate", Allow: true, Binary: bin})
		go s.mitmHTTPS(clientConn, bufrw.Reader, backend, host, port, eng, bin)
		return
	}

	s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: dec.Reason, Allow: true, Binary: bin})
	// Drain any buffered bytes into the tunnel.
	go tunnelWithBuf(backend, clientConn, bufrw.Reader)
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
	_ = clientTLS.SetDeadline(time.Now().Add(30 * time.Second))
	if err := clientTLS.Handshake(); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "client tls: " + err.Error(), Allow: false})
		return
	}
	_ = clientTLS.SetDeadline(time.Time{})

	upTLS := tls.Client(backend, upTLSCfg)
	_ = upTLS.SetDeadline(time.Now().Add(30 * time.Second))
	if err := upTLS.Handshake(); err != nil {
		s.logAudit(auditEvent{Action: "dial_error", Host: host, Port: port, Reason: "upstream tls: " + err.Error(), Allow: true})
		return
	}
	_ = upTLS.SetDeadline(time.Time{})

	clientBR := bufio.NewReader(clientTLS)
	upBR := bufio.NewReader(upTLS)

	s.mu.RLock()
	secrets := s.secrets
	s.mu.RUnlock()

	for {
		_ = clientTLS.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			return
		}
		pathOnly := req.URL.EscapedPath()
		if pathOnly == "" {
			pathOnly = "/"
		}
		dec, err := s.decideHTTP(req, eng, host, port, pathOnly, binary)
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
				Body:       io.NopCloser(strings.NewReader("whaleshell-proxy: denied\n")),
			}
			resp.Header.Set("Content-Type", "text/plain")
			resp.Header.Set("Connection", "close")
			resp.ContentLength = int64(len("whaleshell-proxy: denied\n"))
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

		if err := s.runMiddleware(req.Context(), host, port, req.Method, pathOnly, req.Header); err != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: err.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "whaleshell-proxy: middleware denied\n"
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
			msg := "whaleshell-proxy: credential_endpoint_mismatch\n"
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
		if err := RewriteHTTPRequest(req, rewSecrets); err != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: "credential rewrite: " + err.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "whaleshell-proxy: credential rewrite failed\n"
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
		if err := outReq.Write(upTLS); err != nil {
			_ = req.Body.Close()
			return
		}
		_ = upTLS.SetReadDeadline(time.Now().Add(5 * time.Minute))
		resp, err := http.ReadResponse(upBR, outReq)
		if err != nil {
			_ = req.Body.Close()
			return
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
			if mr := dec.Matched; mr != nil {
				wsRewrite = mr.Rule.WebsocketCredentialRewrite
				proto = mr.Rule.Protocol
				bound = mr.Rule.CredentialKeys
			}
			s.relayWebsocket(clientBR, clientTLS, upBR, upTLS, host, port, pathOnly, eng, secrets, bound, wsRewrite, proto, binary)
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

func (s *Server) relayWebsocket(clientBR *bufio.Reader, client io.Writer, upBR *bufio.Reader, up io.Writer, host string, port int, pathOnly string, eng engine.PolicyEngine, secrets SecretStore, boundKeys []string, rewriteText bool, protocol string, binary string) {
	errCh := make(chan struct{}, 2)
	go func() {
		defer func() { errCh <- struct{}{} }()
		for {
			fr, err := readWSFrame(clientBR)
			if err != nil {
				return
			}
			switch fr.Opcode {
			case wsOpcodeText:
				method := policy.MethodWebsocketText
				payload := fr.Payload
				if strings.EqualFold(protocol, policy.ProtocolGraphQL) {
					okPass, meth, err := classifyGraphQLWS(payload)
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
					method = meth
				}
				dec, err := eng.DecideHTTP(context.Background(), engine.HTTPRequest{
					Host: host, Port: port, Method: method, Path: pathOnly, Binary: binary,
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
					rew, bindErr := SecretsForEndpoint(secrets, boundKeys, used)
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
			case wsOpcodeBinary, wsOpcodePing, wsOpcodePong, wsOpcodeContinuation:
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

// classifyGraphQLWS returns (passWithoutL7, method, err).
// Control messages pass; subscribe/start require MethodSubscribe; other types deny.
func classifyGraphQLWS(payload []byte) (pass bool, method string, err error) {
	var msg struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return false, "", fmt.Errorf("graphql-ws: invalid json")
	}
	switch strings.ToLower(strings.TrimSpace(msg.Type)) {
	case "connection_init", "ping", "pong", "complete", "stop", "connection_terminate", "connection_ack", "ka":
		return true, "", nil
	case "subscribe", "start":
		return false, policy.MethodSubscribe, nil
	default:
		return false, "", fmt.Errorf("graphql-ws: unsupported type %q", msg.Type)
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
