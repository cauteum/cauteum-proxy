// Package middleware runs optional HTTP/WS stages before credential rewrite.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Request is the inspectable egress request passed to stages.
type Request struct {
	Scheme  string            `json:"scheme"`
	Host    string            `json:"host"`
	Port    int               `json:"port"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

// Response is the normalized upstream response visible to response stages.
type Response struct {
	StatusCode int
	Headers    http.Header
	Trailers   http.Header
	Body       []byte
}

// ResponseDecision is the result of response middleware evaluation.
type ResponseDecision struct {
	Allow  bool
	Reason string
}

type WebSocketRequest struct {
	SessionID             string
	Scheme                string
	Host                  string
	Port                  int
	Path                  string
	RequestedSubprotocols []string
}

type WebSocketSession interface {
	Preflight(ctx context.Context) (inspect bool, err error)
	Start(ctx context.Context, selectedSubprotocol string) error
	Message(ctx context.Context, sequence uint64, payload []byte, text bool) (allow bool, replacement []byte, err error)
	Close(reason string) error
}

type WebSocketStage interface {
	OpenWebSocketSession(ctx context.Context, req WebSocketRequest) (WebSocketSession, error)
}

func (p *Pipeline) OpenWebSocketSessions(ctx context.Context, req WebSocketRequest) ([]WebSocketSession, error) {
	if p == nil {
		return nil, nil
	}
	var sessions []WebSocketSession
	for _, stage := range p.Stages {
		wsStage, ok := stage.(WebSocketStage)
		if !ok {
			continue
		}
		session, err := wsStage.OpenWebSocketSession(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("middleware %s websocket: %w", stage.Name(), err)
		}
		inspect, err := session.Preflight(ctx)
		if err != nil {
			_ = session.Close("preflight failure")
			return nil, err
		}
		if inspect {
			sessions = append(sessions, session)
		} else {
			_ = session.Close("stage skipped")
		}
	}
	return sessions, nil
}

// Decision is allow/deny (+ optional header mutations).
type Decision struct {
	Allow           bool              `json:"allow"`
	Reason          string            `json:"reason,omitempty"`
	MutateHeaders   map[string]string `json:"mutate_headers,omitempty"`
	HeaderMutations []HeaderMutation  `json:"header_mutations,omitempty"`
	RemoveHeaders   []string          `json:"remove_headers,omitempty"`
	Body            []byte            `json:"body,omitempty"`
	HasBody         bool              `json:"has_body,omitempty"`
}

type HeaderMutation struct {
	Name   string
	Value  string
	Remove bool
	Append bool
	Skip   bool
}

// Stage evaluates one middleware hop.
type Stage interface {
	Name() string
	Evaluate(ctx context.Context, req Request) (Decision, error)
}

// ResponseStage optionally evaluates the upstream response before delivery.
// Request-only stages intentionally do not need to implement this interface.
type ResponseStage interface {
	EvaluateResponse(ctx context.Context, req Request, resp *Response) (ResponseDecision, error)
}

// Pipeline runs stages in order; first deny wins. Empty pipeline = allow.
type Pipeline struct {
	Stages []Stage
}

func (p *Pipeline) HasResponseStages() bool {
	if p == nil {
		return false
	}
	for _, stage := range p.Stages {
		if _, ok := stage.(ResponseStage); ok {
			return true
		}
	}
	return false
}

// Run evaluates all stages.
func (p *Pipeline) Run(ctx context.Context, req Request) (Decision, error) {
	if p == nil || len(p.Stages) == 0 {
		return Decision{Allow: true, Reason: "no middleware"}, nil
	}
	acc := map[string]string{}
	bodySet := req.Body != nil
	var accHeaderMutations []HeaderMutation
	var accRemovedHeaders []string
	for _, s := range p.Stages {
		dec, err := s.Evaluate(ctx, req)
		if err != nil {
			return Decision{}, fmt.Errorf("middleware %s: %w", s.Name(), err)
		}
		if !dec.Allow {
			if dec.Reason == "" {
				dec.Reason = "denied by " + s.Name()
			}
			return dec, nil
		}
		handledHeaders := map[string]struct{}{}
		for _, mutation := range dec.HeaderMutations {
			accHeaderMutations = append(accHeaderMutations, mutation)
			handledHeaders[mutation.Name] = struct{}{}
		}
		for k, v := range dec.MutateHeaders {
			if _, handled := handledHeaders[k]; handled {
				continue
			}
			if req.Headers == nil {
				req.Headers = map[string]string{}
			}
			req.Headers[k] = v
			acc[k] = v
		}
		for _, mutation := range dec.HeaderMutations {
			if mutation.Remove {
				delete(req.Headers, mutation.Name)
				continue
			}
			if mutation.Skip && req.Headers[mutation.Name] != "" {
				continue
			}
			if mutation.Append && req.Headers[mutation.Name] != "" {
				req.Headers[mutation.Name] += ", " + mutation.Value
			} else {
				req.Headers[mutation.Name] = mutation.Value
			}
			acc[mutation.Name] = req.Headers[mutation.Name]
		}
		for _, name := range dec.RemoveHeaders {
			accRemovedHeaders = append(accRemovedHeaders, name)
			delete(req.Headers, name)
		}
		if dec.HasBody {
			req.Body = append([]byte(nil), dec.Body...)
			bodySet = true
		}
	}
	return Decision{Allow: true, Reason: "middleware allow", MutateHeaders: acc, HeaderMutations: accHeaderMutations, RemoveHeaders: accRemovedHeaders, HasBody: bodySet, Body: append([]byte(nil), req.Body...)}, nil
}

// RunResponse evaluates response-capable stages in registration order.
func (p *Pipeline) RunResponse(ctx context.Context, req Request, resp *Response) error {
	if p == nil || resp == nil {
		return nil
	}
	for _, stage := range p.Stages {
		responseStage, ok := stage.(ResponseStage)
		if !ok {
			continue
		}
		decision, err := responseStage.EvaluateResponse(ctx, req, resp)
		if err != nil {
			return fmt.Errorf("middleware %s response: %w", stage.Name(), err)
		}
		if !decision.Allow {
			if decision.Reason == "" {
				decision.Reason = "denied by " + stage.Name()
			}
			return fmt.Errorf("%s", decision.Reason)
		}
	}
	return nil
}

// rejectedConfigStage prevents removed or unsupported security configuration
// from silently disappearing and turning into an allow decision.
type rejectedConfigStage struct {
	Label  string
	Reason string
}

func (s *rejectedConfigStage) Name() string { return s.Label }

func (s *rejectedConfigStage) Evaluate(context.Context, Request) (Decision, error) {
	return Decision{Allow: false, Reason: s.Reason}, nil
}

// remoteStage POSTs the request JSON to URL and expects a Decision JSON body.
type remoteStage struct {
	URL        string
	FailClosed bool
	HTTP       *http.Client
	Label      string
}

func (r *remoteStage) Name() string {
	if r.Label != "" {
		return r.Label
	}
	return "remote"
}

func (r *remoteStage) Evaluate(ctx context.Context, req Request) (Decision, error) {
	cli := r.HTTP
	if cli == nil {
		cli = &http.Client{Timeout: defaultClientTimeout}
	}
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(httpReq)
	if err != nil {
		if r.FailClosed {
			return Decision{Allow: false, Reason: "remote stage unreachable"}, nil
		}
		return Decision{Allow: true, Reason: "remote stage fail-open"}, nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxRemoteStageBody))
	if int64(len(b)) >= maxRemoteStageBody {
		if r.FailClosed {
			return Decision{Allow: false, Reason: "remote stage response too large"}, nil
		}
		return Decision{Allow: true, Reason: "remote stage fail-open oversized"}, nil
	}
	if res.StatusCode >= 300 {
		if r.FailClosed {
			return Decision{Allow: false, Reason: fmt.Sprintf("remote stage http %s", res.Status)}, nil
		}
		return Decision{Allow: true, Reason: "remote stage fail-open http"}, nil
	}
	var dec Decision
	if err := json.Unmarshal(b, &dec); err != nil {
		if r.FailClosed {
			return Decision{Allow: false, Reason: "remote stage bad json"}, nil
		}
		return Decision{Allow: true, Reason: "remote stage fail-open json"}, nil
	}
	return dec, nil
}

// maxRemoteStageBody caps remote middleware HTTP responses (decision JSON).
const maxRemoteStageBody = 1 << 20 // 1 MiB
