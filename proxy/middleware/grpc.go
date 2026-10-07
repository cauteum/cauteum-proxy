package middleware

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	middlewarev1 "github.com/whaleshell/whaleshell-core/upstreamproto/middlewarev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// GRPCStage is the typed SupervisorMiddleware request-stage adapter. It is
// intentionally created from gateway-provided config; the proxy never trusts
// arbitrary middleware endpoints from workload environment.
type GRPCStage struct {
	name       string
	client     middlewarev1.SupervisorMiddlewareClient
	conn       grpc.ClientConnInterface
	timeout    time.Duration
	failClosed bool
	config     *structpb.Struct
	maxPayload uint64
	include    []string
	exclude    []string
}

type GRPCStageConfig struct {
	Name            string
	Endpoint        string
	Timeout         time.Duration
	FailClosed      bool
	Config          *structpb.Struct
	TLSRoots        *x509.CertPool
	MaxPayloadBytes uint64
	Order           int32
	Include         []string
	Exclude         []string
}

func NewGRPCStage(cfg GRPCStageConfig) (*GRPCStage, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		return nil, fmt.Errorf("middleware name is required")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("middleware %q endpoint must be an http(s) URL", name)
	}
	var opts []grpc.DialOption
	if u.Scheme == "https" {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: cfg.TLSRoots})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	conn, err := grpc.NewClient(u.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("middleware %q dial: %w", name, err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 500 * time.Millisecond
	}
	if cfg.MaxPayloadBytes == 0 {
		cfg.MaxPayloadBytes = 4 << 20
	}
	return &GRPCStage{name: name, client: middlewarev1.NewSupervisorMiddlewareClient(conn), conn: conn, timeout: cfg.Timeout, failClosed: cfg.FailClosed, config: cfg.Config, maxPayload: cfg.MaxPayloadBytes, include: append([]string(nil), cfg.Include...), exclude: append([]string(nil), cfg.Exclude...)}, nil
}

func (s *GRPCStage) EvaluateResponse(ctx context.Context, req Request, resp *Response) (ResponseDecision, error) {
	if !s.matchesHost(req.Host) {
		return ResponseDecision{Allow: true}, nil
	}
	if resp.Trailers == nil {
		resp.Trailers = make(http.Header)
	}
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := middlewarev1.NewHttpResponsePreReturnClient(s.conn).Evaluate(streamCtx)
	if err != nil {
		return s.responseFailure("response middleware unavailable")
	}
	if err := sendResponseEvent(streamCtx, s.timeout, stream, &middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Preflight{Preflight: &middlewarev1.HttpResponsePreflight{
		StatusCode: uint32(resp.StatusCode), Headers: responseHeaders(resp.Headers), MiddlewareName: s.name, Config: s.config,
		MaxPayloadBytes: s.maxPayload, PermittedBodyModes: []middlewarev1.HttpResponseBodyMode{
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
			middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES,
		},
	}}}); err != nil {
		return s.responseFailure("response middleware preflight failed")
	}
	preflight, err := recvResponseEvent(streamCtx, s.timeout, stream)
	if err != nil {
		return s.responseFailure("response middleware preflight unavailable")
	}
	result := preflight.GetPreflightResult()
	if result == nil {
		return s.responseFailure("response middleware returned invalid preflight")
	}
	if result.GetBlockDelivery() != nil {
		return ResponseDecision{Allow: false, Reason: "response middleware denied"}, nil
	}
	if result.GetSkip() != nil || result.GetInspect() == nil {
		_ = sendResponseSessionEnd(stream, middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_STAGE_SKIPPED)
		return ResponseDecision{Allow: true}, nil
	}
	inspect := result.GetInspect()
	applyHeaderMutations(resp.Headers, inspect.GetHeaderMutations())
	if inspect.GetBodyMode() == middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY || responseBodyless(req, resp) {
		_ = sendResponseSessionEnd(stream, middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL)
		return ResponseDecision{Allow: true}, nil
	}
	limit := int(s.maxPayload)
	if limit <= 0 || limit > 4<<20 {
		limit = 4 << 20
	}
	chunkSize := limit
	if inspect.GetBodyMode() == middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES && chunkSize > 64<<10 {
		chunkSize = 64 << 10
	}
	if inspect.GetBodyMode() == middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES && len(resp.Body) > limit {
		return s.responseFailure("response body exceeds middleware payload limit")
	}
	var output []byte
	for offset, sequence := 0, uint64(1); offset < len(resp.Body) || sequence == 1; sequence++ {
		end := offset + chunkSize
		if end > len(resp.Body) {
			end = len(resp.Body)
		}
		unit := &middlewarev1.HttpResponseBodyUnit{Sequence: sequence, EndOfStream: end == len(resp.Body), Payload: &middlewarev1.HttpResponseBodyUnit_Data{Data: append([]byte(nil), resp.Body[offset:end]...)}}
		if err := sendResponseEvent(streamCtx, s.timeout, stream, &middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Body{Body: unit}}); err != nil {
			return s.responseFailure("response middleware body send failed")
		}
		bodyResult, err := recvResponseEvent(streamCtx, s.timeout, stream)
		if err != nil {
			return s.responseFailure("response middleware body result unavailable")
		}
		result := bodyResult.GetBodyResult()
		if result == nil || result.GetSequence() != sequence {
			return s.responseFailure("response middleware returned invalid body result")
		}
		switch {
		case result.GetBlockDelivery() != nil:
			return ResponseDecision{Allow: false, Reason: "response middleware denied"}, nil
		case result.GetTransform() != nil:
			output = append(output, result.GetTransform().GetData()...)
		case result.GetSkipRemaining() != nil:
			if pass := result.GetSkipRemaining().GetPassThrough(); pass != nil {
				output = append(output, resp.Body[offset:end]...)
			} else if transform := result.GetSkipRemaining().GetTransform(); transform != nil {
				output = append(output, transform.GetData()...)
			}
			output = append(output, resp.Body[end:]...)
			resp.Body = output
			_ = sendResponseSessionEnd(stream, middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL)
			return ResponseDecision{Allow: true}, nil
		default:
			output = append(output, resp.Body[offset:end]...)
		}
		offset = end
		if end == len(resp.Body) {
			break
		}
	}
	resp.Body = output
	if err := sendResponseTrailers(streamCtx, s.timeout, stream, resp.Trailers); err != nil {
		return s.responseFailure("response middleware trailers failed")
	}
	_ = sendResponseSessionEnd(stream, middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL)
	return ResponseDecision{Allow: true}, nil
}

func sendResponseTrailers(ctx context.Context, timeout time.Duration, stream middlewarev1.HttpResponsePreReturn_EvaluateClient, trailers http.Header) error {
	if err := sendResponseEvent(ctx, timeout, stream, &middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_Trailers{Trailers: &middlewarev1.HttpResponseTrailers{Headers: responseHeaders(trailers)}}}); err != nil {
		return err
	}
	result, err := recvResponseEvent(ctx, timeout, stream)
	if err != nil || result.GetTrailersResult() == nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("invalid response trailers result")
	}
	if err := applyTrailerMutations(trailers, result.GetTrailersResult().GetTrailerMutations()); err != nil {
		return err
	}
	return nil
}

func sendResponseEvent(ctx context.Context, timeout time.Duration, stream middlewarev1.HttpResponsePreReturn_EvaluateClient, event *middlewarev1.HttpResponseEvent) error {
	done := make(chan error, 1)
	go func() { done <- stream.Send(event) }()
	if timeout <= 0 {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func recvResponseEvent(ctx context.Context, timeout time.Duration, stream middlewarev1.HttpResponsePreReturn_EvaluateClient) (*middlewarev1.HttpResponseEventResult, error) {
	type result struct {
		value *middlewarev1.HttpResponseEventResult
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := stream.Recv()
		done <- result{value: value, err: err}
	}()
	if timeout <= 0 {
		select {
		case result := <-done:
			return result.value, result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.value, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, context.DeadlineExceeded
	}
}

func responseBodyless(req Request, resp *Response) bool {
	if strings.EqualFold(req.Method, http.MethodHead) || resp.StatusCode < 200 {
		return true
	}
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotModified:
		return true
	default:
		return false
	}
}

func applyTrailerMutations(headers http.Header, mutations []*middlewarev1.HeaderMutation) error {
	for _, mutation := range mutations {
		if mutation == nil {
			return fmt.Errorf("response middleware returned a nil trailer mutation")
		}
		var name string
		if write := mutation.GetWrite(); write != nil {
			name = write.GetName()
			if strings.TrimSpace(name) == "" || isProtectedTrailer(name) {
				return fmt.Errorf("response middleware attempted to mutate protected trailer %q", name)
			}
			if len(headers.Values(name)) == 0 {
				return fmt.Errorf("response middleware attempted to create trailer %q", name)
			}
		} else if remove := mutation.GetRemove(); remove != nil {
			name = remove.GetName()
			if isProtectedTrailer(name) {
				return fmt.Errorf("response middleware attempted to remove protected trailer %q", name)
			}
		} else {
			return fmt.Errorf("response middleware returned an invalid trailer mutation")
		}
	}
	applyHeaderMutations(headers, mutations)
	return nil
}

func isProtectedTrailer(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "content-length" || name == "transfer-encoding" || name == "connection" || name == "upgrade" || name == "host" || name == "trailer" || name == "te" || name == "keep-alive" || strings.HasPrefix(name, "proxy-")
}

func (s *GRPCStage) responseFailure(reason string) (ResponseDecision, error) {
	if s.failClosed {
		return ResponseDecision{Allow: false, Reason: reason}, nil
	}
	return ResponseDecision{Allow: true, Reason: "response middleware fail-open"}, nil
}

func sendResponseSessionEnd(stream middlewarev1.HttpResponsePreReturn_EvaluateClient, reason middlewarev1.MiddlewareSessionEndReason) error {
	err := stream.Send(&middlewarev1.HttpResponseEvent{Event: &middlewarev1.HttpResponseEvent_SessionEnd{SessionEnd: &middlewarev1.MiddlewareSessionEnd{Reason: reason}}})
	if err != nil {
		return err
	}
	return stream.CloseSend()
}

func responseHeaders(headers http.Header) []*middlewarev1.HttpHeader {
	var out []*middlewarev1.HttpHeader
	for name, values := range headers {
		for _, value := range values {
			out = append(out, &middlewarev1.HttpHeader{Name: strings.ToLower(name), Value: strings.TrimSpace(value)})
		}
	}
	return out
}

func applyHeaderMutations(headers http.Header, mutations []*middlewarev1.HeaderMutation) {
	for _, mutation := range mutations {
		if mutation == nil {
			continue
		}
		if write := mutation.GetWrite(); write != nil {
			switch write.GetOnExisting() {
			case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_APPEND:
				headers.Add(write.GetName(), write.GetValue())
			case middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_SKIP:
				if len(headers.Values(write.GetName())) == 0 {
					headers.Set(write.GetName(), write.GetValue())
				}
			default:
				headers.Set(write.GetName(), write.GetValue())
			}
		} else if remove := mutation.GetRemove(); remove != nil {
			headers.Del(remove.GetName())
		}
	}
}

func (s *GRPCStage) Name() string { return s.name }

func (s *GRPCStage) Evaluate(ctx context.Context, req Request) (Decision, error) {
	if !s.matchesHost(req.Host) {
		return Decision{Allow: true, Reason: "middleware selector skipped"}, nil
	}
	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	headers := make([]*middlewarev1.HttpHeader, 0, len(req.Headers))
	for name, value := range req.Headers {
		headers = append(headers, &middlewarev1.HttpHeader{Name: strings.ToLower(strings.TrimSpace(name)), Value: strings.TrimSpace(value)})
	}
	result, err := s.client.EvaluateHttpRequest(callCtx, &middlewarev1.HttpRequestEvaluation{
		Phase:          middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Config:         s.config,
		Target:         &middlewarev1.HttpRequestTarget{Scheme: "http", Host: req.Host, Port: uint32(req.Port), Method: req.Method, Path: req.Path},
		Headers:        headers,
		Body:           req.Body,
		MiddlewareName: s.name,
	})
	if err != nil {
		if s.failClosed {
			return Decision{Allow: false, Reason: "supervisor middleware unavailable"}, nil
		}
		return Decision{Allow: true, Reason: "supervisor middleware fail-open"}, nil
	}
	if result == nil {
		if s.failClosed {
			return Decision{Allow: false, Reason: "supervisor middleware returned no result"}, nil
		}
		return Decision{Allow: true, Reason: "supervisor middleware fail-open"}, nil
	}
	decision := Decision{Allow: result.GetDecision() == middlewarev1.Decision_DECISION_ALLOW, Reason: result.GetReason(), MutateHeaders: map[string]string{}, HasBody: result.GetHasBody(), Body: append([]byte(nil), result.GetBody()...)}
	for _, mutation := range result.GetHeaderMutations() {
		if mutation == nil {
			continue
		}
		if write := mutation.GetWrite(); write != nil {
			decision.MutateHeaders[write.GetName()] = write.GetValue()
			decision.HeaderMutations = append(decision.HeaderMutations, HeaderMutation{Name: write.GetName(), Value: write.GetValue(), Append: write.GetOnExisting() == middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_APPEND, Skip: write.GetOnExisting() == middlewarev1.ExistingHeaderAction_EXISTING_HEADER_ACTION_SKIP})
		} else if remove := mutation.GetRemove(); remove != nil {
			decision.RemoveHeaders = append(decision.RemoveHeaders, remove.GetName())
			decision.HeaderMutations = append(decision.HeaderMutations, HeaderMutation{Name: remove.GetName(), Remove: true})
		}
	}
	if !decision.Allow && decision.Reason == "" {
		decision.Reason = "supervisor middleware denied request"
	}
	return decision, nil
}

type grpcWebSocketSession struct {
	stage  *GRPCStage
	stream grpc.BidiStreamingClient[middlewarev1.WebSocketSessionEvent, middlewarev1.WebSocketSessionEventResult]
	req    WebSocketRequest
	closed bool
}

func (s *GRPCStage) OpenWebSocketSession(ctx context.Context, req WebSocketRequest) (WebSocketSession, error) {
	if !s.matchesHost(req.Host) {
		return &grpcWebSocketSession{stage: s, req: req, closed: true}, nil
	}
	stream, err := s.client.EvaluateWebSocketSession(ctx)
	if err != nil {
		if s.failClosed {
			return nil, fmt.Errorf("supervisor websocket middleware unavailable")
		}
		return &grpcWebSocketSession{stage: s, req: req, closed: true}, nil
	}
	return &grpcWebSocketSession{stage: s, stream: stream, req: req}, nil
}

func (s *grpcWebSocketSession) Preflight(ctx context.Context) (bool, error) {
	if s.closed {
		return false, nil
	}
	callCtx, cancel := context.WithTimeout(ctx, s.stage.timeout)
	defer cancel()
	_ = callCtx
	target := &middlewarev1.HttpRequestTarget{Scheme: "wss", Host: s.req.Host, Port: uint32(s.req.Port), Method: http.MethodGet, Path: s.req.Path}
	err := s.stream.Send(&middlewarev1.WebSocketSessionEvent{Event: &middlewarev1.WebSocketSessionEvent_Preflight{Preflight: &middlewarev1.WebSocketPreflight{SessionId: s.req.SessionID, Phase: middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS, Target: target, RequestedSubprotocols: append([]string(nil), s.req.RequestedSubprotocols...), MiddlewareName: s.stage.name, Config: s.stage.config}}})
	if err != nil {
		return s.fail("websocket preflight send failed")
	}
	result, err := s.stream.Recv()
	if err != nil {
		return s.fail("websocket preflight result unavailable")
	}
	decision := result.GetPreflightDecision()
	if decision == nil {
		return s.fail("websocket preflight returned invalid result")
	}
	switch decision.GetAction() {
	case middlewarev1.WebSocketPreflightAction_WEB_SOCKET_PREFLIGHT_ACTION_INSPECT:
		return true, nil
	case middlewarev1.WebSocketPreflightAction_WEB_SOCKET_PREFLIGHT_ACTION_SKIP:
		return false, nil
	case middlewarev1.WebSocketPreflightAction_WEB_SOCKET_PREFLIGHT_ACTION_DENY:
		return false, fmt.Errorf("websocket middleware denied")
	default:
		return s.fail("websocket preflight returned unspecified action")
	}
}

func (s *grpcWebSocketSession) Start(ctx context.Context, selectedSubprotocol string) error {
	if s.closed {
		return nil
	}
	return s.stream.Send(&middlewarev1.WebSocketSessionEvent{Event: &middlewarev1.WebSocketSessionEvent_SessionStart{SessionStart: &middlewarev1.WebSocketSessionStart{SelectedSubprotocol: selectedSubprotocol}}})
}

func (s *grpcWebSocketSession) Message(ctx context.Context, sequence uint64, payload []byte, text bool) (bool, []byte, error) {
	if s.closed {
		return true, payload, nil
	}
	callCtx, cancel := context.WithTimeout(ctx, s.stage.timeout)
	defer cancel()
	_ = callCtx
	message := &middlewarev1.WebSocketMessage{Sequence: sequence}
	if text {
		message.Payload = &middlewarev1.WebSocketMessage_Text{Text: string(payload)}
	} else {
		message.Payload = &middlewarev1.WebSocketMessage_Binary{Binary: append([]byte(nil), payload...)}
	}
	if err := s.stream.Send(&middlewarev1.WebSocketSessionEvent{Event: &middlewarev1.WebSocketSessionEvent_Message{Message: message}}); err != nil {
		return s.failMessage("websocket message send failed", payload)
	}
	result, err := s.stream.Recv()
	if err != nil {
		return s.failMessage("websocket message result unavailable", payload)
	}
	messageResult := result.GetMessageResult()
	if messageResult == nil || messageResult.GetSequence() != sequence {
		return s.failMessage("websocket message result invalid", payload)
	}
	decision := messageResult.GetDecision()
	if decision == middlewarev1.Decision_DECISION_DENY {
		return false, nil, nil
	}
	if decision != middlewarev1.Decision_DECISION_ALLOW {
		return s.failMessage("websocket message decision unspecified", payload)
	}
	if text {
		if replacement := messageResult.GetText(); replacement != "" || messageResult.GetReplacement() != nil {
			if _, ok := messageResult.GetReplacement().(*middlewarev1.WebSocketMessageResult_Text); ok {
				return true, []byte(replacement), nil
			}
		}
	} else if replacement, ok := messageResult.GetReplacement().(*middlewarev1.WebSocketMessageResult_Binary); ok {
		return true, append([]byte(nil), replacement.Binary...), nil
	}
	return true, payload, nil
}

func (s *grpcWebSocketSession) Close(reason string) error {
	if s.closed {
		return nil
	}
	s.closed = true
	if err := s.stream.Send(&middlewarev1.WebSocketSessionEvent{Event: &middlewarev1.WebSocketSessionEvent_SessionEnd{SessionEnd: &middlewarev1.MiddlewareSessionEnd{Reason: middlewarev1.MiddlewareSessionEndReason_MIDDLEWARE_SESSION_END_REASON_NORMAL}}}); err != nil {
		return err
	}
	return s.stream.CloseSend()
}

func (s *grpcWebSocketSession) fail(reason string) (bool, error) {
	if s.stage.failClosed {
		return false, fmt.Errorf("%s", reason)
	}
	_ = s.Close(reason)
	return false, nil
}

func (s *grpcWebSocketSession) failMessage(reason string, payload []byte) (bool, []byte, error) {
	if s.stage.failClosed {
		return false, nil, fmt.Errorf("%s", reason)
	}
	_ = s.Close(reason)
	return true, payload, nil
}

func (s *GRPCStage) matchesHost(host string) bool {
	if len(s.include) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	included := false
	for _, pattern := range s.include {
		if hostPatternMatch(pattern, host) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, pattern := range s.exclude {
		if hostPatternMatch(pattern, host) {
			return false
		}
	}
	return true
}

func hostPatternMatch(pattern, host string) bool {
	left := strings.Split(strings.ToLower(strings.TrimSuffix(pattern, ".")), ".")
	right := strings.Split(host, ".")
	var match func(int, int) bool
	match = func(pi, hi int) bool {
		if pi == len(left) {
			return hi == len(right)
		}
		if left[pi] == "**" {
			for n := hi; n <= len(right); n++ {
				if match(pi+1, n) {
					return true
				}
			}
			return false
		}
		if hi == len(right) {
			return false
		}
		ok, err := path.Match(left[pi], right[hi])
		return err == nil && ok && match(pi+1, hi+1)
	}
	return match(0, 0)
}
