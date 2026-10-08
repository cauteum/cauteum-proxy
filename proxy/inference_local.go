package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// InferenceLocalHost is the OpenShell privacy-router hostname.
const InferenceLocalHost = "inference.local"

// InferenceConfig is loaded from CAUTEUM_INFERENCE_* env (sidecar).
type InferenceConfig struct {
	Upstream   string // e.g. https://integrate.api.nvidia.com
	Model      string
	TimeoutSec int
	APIKey     string // raw secret for upstream Authorization
}

// LoadInferenceFromEnviron reads CAUTEUM_INFERENCE_UPSTREAM, CAUTEUM_INFERENCE_MODEL,
// CAUTEUM_INFERENCE_TIMEOUT, CAUTEUM_INFERENCE_API_KEY.
func LoadInferenceFromEnviron(environ []string) InferenceConfig {
	cfg := InferenceConfig{TimeoutSec: 60}
	for _, e := range environ {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		switch k {
		case "CAUTEUM_INFERENCE_UPSTREAM":
			cfg.Upstream = strings.TrimRight(v, "/")
		case "CAUTEUM_INFERENCE_MODEL":
			cfg.Model = v
		case "CAUTEUM_INFERENCE_TIMEOUT":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.TimeoutSec = n
			}
		case "CAUTEUM_INFERENCE_API_KEY":
			cfg.APIKey = v
		}
	}
	if cfg.Upstream == "" {
		cfg.Upstream = strings.TrimRight(os.Getenv("CAUTEUM_INFERENCE_UPSTREAM"), "/")
	}
	return cfg
}

func (s *Server) mitmHandshake(client net.Conn, host string) (*tls.Conn, error) {
	s.mu.RLock()
	ca := s.ca
	s.mu.RUnlock()
	if ca == nil {
		return nil, fmt.Errorf("mitm ca missing")
	}
	tlsCfg, err := ca.ServerTLSConfig(host)
	if err != nil {
		return nil, err
	}
	clientTLS := tls.Server(client, tlsCfg)
	if err := clientTLS.Handshake(); err != nil {
		return nil, err
	}
	return clientTLS, nil
}

func (s *Server) isInferenceLocal(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == InferenceLocalHost || h == "inference.cauteum.local"
}

// handleInferenceLocal terminates CONNECT and reverse-proxies to the configured upstream.
func (s *Server) handleInferenceLocal(w http.ResponseWriter, r *http.Request, client net.Conn) {
	cfg := LoadInferenceFromEnviron(os.Environ())
	if cfg.Upstream == "" {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		s.logAudit(auditEvent{Action: "deny", Host: InferenceLocalHost, Reason: "inference upstream not configured", Allow: false})
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsConn, err := s.mitmHandshake(client, InferenceLocalHost)
	if err != nil {
		s.logAudit(auditEvent{Action: "error", Host: InferenceLocalHost, Reason: err.Error(), Allow: false})
		return
	}
	defer tlsConn.Close()

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if err := s.proxyInferenceRequest(tlsConn, req, cfg); err != nil {
			s.logAudit(auditEvent{Action: "error", Host: InferenceLocalHost, Reason: err.Error(), Allow: false})
			return
		}
	}
}

func (s *Server) proxyInferenceRequest(w io.Writer, req *http.Request, cfg InferenceConfig) error {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 8<<20))
	_ = req.Body.Close()
	if len(body) > 0 && cfg.Model != "" {
		body = rewriteModelJSON(body, cfg.Model)
	}
	upURL := cfg.Upstream + req.URL.RequestURI()
	upReq, err := http.NewRequest(req.Method, upURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// Strip caller auth; inject gateway-managed key.
	upReq.Header = http.Header{}
	for k, vv := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "host" || lk == "content-length" {
			continue
		}
		for _, v := range vv {
			upReq.Header.Add(k, v)
		}
	}
	if cfg.APIKey != "" {
		upReq.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	upReq.Header.Set("Content-Type", firstOr(req.Header.Get("Content-Type"), "application/json"))
	client := &http.Client{Timeout: time.Duration(cfg.TimeoutSec) * time.Second}
	res, err := client.Do(upReq)
	if err != nil {
		fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\n\r\n%s", len(err.Error()), err.Error())
		return nil
	}
	defer res.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", res.StatusCode, res.Status)
	buf.WriteString("Content-Length: " + strconv.Itoa(len(respBody)) + "\r\n")
	ct := res.Header.Get("Content-Type")
	if ct != "" {
		buf.WriteString("Content-Type: " + ct + "\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(respBody)
	_, err = w.Write(buf.Bytes())
	s.logAudit(auditEvent{Action: "allow", Host: InferenceLocalHost, Reason: "inference.local→" + cfg.Upstream, Allow: true})
	return err
}

func rewriteModelJSON(body []byte, model string) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["model"] = model
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

func firstOr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
