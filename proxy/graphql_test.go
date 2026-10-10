package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cauteum-core/engine"
	"github.com/cautem/cauteum-core/policy"
)

func TestParseGraphQLRequestExtractsOperationAndRootFields(t *testing.T) {
	body := `query Dashboard { alias: dashboard { nested { ignored } } ...More ... on Query { status } } fragment More on Query { profile }`
	req := httptest.NewRequest(http.MethodPost, "https://gql.example/graphql", strings.NewReader(`{"query":`+`"`+strings.ReplaceAll(body, `"`, `\"`)+`"}`))
	ops, err := parseGraphQLRequest(req, policy.AllowRule{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].OperationType != "query" || ops[0].OperationName != "Dashboard" {
		t.Fatalf("operations=%+v", ops)
	}
	want := []string{"dashboard", "profile", "status"}
	if strings.Join(ops[0].Fields, ",") != strings.Join(want, ",") {
		t.Fatalf("root fields=%v want %v", ops[0].Fields, want)
	}
}

func TestGraphQLBatchRequiresEveryOperationAllowed(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: "gql.example", Port: 443, TLS: policy.TLSTerminate, Protocol: policy.ProtocolGraphQL,
		Rules: []policy.L7Rule{{Allow: &policy.L7Allow{OperationType: "query", Fields: []string{"public*"}}}},
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	request := func(body string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://gql.example/graphql", strings.NewReader(body))
		req.RequestURI = "/graphql"
		return req
	}
	allowed, err := server.decideHTTP(request(`[{"query":"query { publicStatus }"},{"query":"{ publicProfile }"}]`), eng, "gql.example", 443, "/graphql", "")
	if err != nil || !allowed.Allow {
		t.Fatalf("allowed batch=%+v err=%v", allowed, err)
	}
	denied, err := server.decideHTTP(request(`[{"query":"{ publicStatus }"},{"query":"mutation { deleteAccount }"}]`), eng, "gql.example", 443, "/graphql", "")
	if err != nil || denied.Allow {
		t.Fatalf("unsafe batch decision=%+v err=%v", denied, err)
	}
}

func TestParseGraphQLRejectsAmbiguousAndOversizeRequests(t *testing.T) {
	for _, target := range []string{
		"https://gql.example/graphql?query=%7Bok%7D&query=%7Bother%7D",
		"https://gql.example/graphql?id=one&queryId=two",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if _, err := parseGraphQLRequest(req, policy.AllowRule{}); err == nil {
			t.Fatalf("accepted ambiguous request %s", target)
		}
	}
	limit := uint32(8)
	req := httptest.NewRequest(http.MethodPost, "https://gql.example/graphql", strings.NewReader(`{"query":"{long}"}`))
	if _, err := parseGraphQLRequest(req, policy.AllowRule{GraphQLMaxBodyBytes: &limit}); err == nil {
		t.Fatal("accepted request larger than configured limit")
	}
}

func TestClassifyGraphQLWebSocketExtractsPolicyOperation(t *testing.T) {
	pass, operation, err := classifyGraphQLWS([]byte(`{"id":"sub-1","type":"subscribe","payload":{"query":"subscription Updates { messageAdded { id } }"}}`))
	if err != nil || pass || operation == nil {
		t.Fatalf("pass=%v operation=%+v err=%v", pass, operation, err)
	}
	if operation.OperationType != "subscription" || operation.OperationName != "Updates" || strings.Join(operation.Fields, ",") != "messageAdded" {
		t.Fatalf("operation=%+v", operation)
	}
	pass, operation, err = classifyGraphQLWS([]byte(`{"type":"connection_init"}`))
	if err != nil || !pass || operation != nil {
		t.Fatalf("control pass=%v operation=%+v err=%v", pass, operation, err)
	}
	for _, payload := range []string{
		`{"type":"subscribe","payload":{"query":"{ x }"}}`,
		`{"id":"1","type":"subscribe","payload":{}}`,
		`{"type":"connection_ack"}`,
	} {
		if _, _, err := classifyGraphQLWS([]byte(payload)); err == nil {
			t.Fatalf("accepted invalid client WebSocket message %s", payload)
		}
	}
}

func TestGraphQLWebSocketOperationRulesAreEnforced(t *testing.T) {
	doc := policy.Document{Version: 1}
	channel := "updates"
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: "gql.example", Port: 443, TLS: policy.TLSTerminate, Protocol: policy.ProtocolWebsocket,
		Rules: []policy.L7Rule{
			{Allow: &policy.L7Allow{Method: http.MethodGet, Path: "/graphql"}},
			{Allow: &policy.L7Allow{OperationType: "subscription", Fields: []string{"messageAdded"}, Query: map[string]policy.QueryMatcher{"channel": {Glob: &channel}}}},
		},
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	if !doc.NetworkAllows()[0].UsesGraphQLOperationRules() {
		t.Fatal("GraphQL operation rules not detected")
	}
	pass, op, err := classifyGraphQLWS([]byte(`{"id":"s","type":"subscribe","payload":{"query":"subscription { messageAdded { id } }"}}`))
	if err != nil || pass {
		t.Fatalf("classify pass=%v err=%v", pass, err)
	}
	allowed, err := eng.DecideHTTP(context.Background(), engine.HTTPRequest{Host: "gql.example", Port: 443, Path: "/graphql", GraphQL: op, Query: map[string][]string{"channel": {"updates"}}})
	if err != nil || !allowed.Allow {
		t.Fatalf("subscription decision=%+v err=%v", allowed, err)
	}
	missingQuery, err := eng.DecideHTTP(context.Background(), engine.HTTPRequest{Host: "gql.example", Port: 443, Path: "/graphql", GraphQL: op})
	if err != nil || missingQuery.Allow {
		t.Fatalf("subscription without its handshake query must be denied: decision=%+v err=%v", missingQuery, err)
	}
	wrongQuery, err := eng.DecideHTTP(context.Background(), engine.HTTPRequest{Host: "gql.example", Port: 443, Path: "/graphql", GraphQL: op, Query: map[string][]string{"channel": {"admin"}}})
	if err != nil || wrongQuery.Allow {
		t.Fatalf("subscription with mismatched handshake query must be denied: decision=%+v err=%v", wrongQuery, err)
	}
	pass, op, err = classifyGraphQLWS([]byte(`{"id":"s","type":"subscribe","payload":{"query":"subscription { adminEvent { id } }"}}`))
	if err != nil || pass {
		t.Fatalf("classify pass=%v err=%v", pass, err)
	}
	denied, err := eng.DecideHTTP(context.Background(), engine.HTTPRequest{Host: "gql.example", Port: 443, Path: "/graphql", GraphQL: op})
	if err != nil || denied.Allow {
		t.Fatalf("admin subscription decision=%+v err=%v", denied, err)
	}
}

func TestRelayGraphQLWebSocketReusesHandshakeQuery(t *testing.T) {
	channel := "updates"
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: "gql.example", Port: 443, TLS: policy.TLSTerminate, Protocol: policy.ProtocolWebsocket,
		Rules: []policy.L7Rule{
			{Allow: &policy.L7Allow{Method: http.MethodGet, Path: "/graphql"}},
			{Allow: &policy.L7Allow{OperationType: "subscription", Fields: []string{"messageAdded"}, Query: map[string]policy.QueryMatcher{"channel": {Glob: &channel}}}},
		},
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	operation := []byte(`{"id":"s","type":"subscribe","payload":{"query":"subscription { messageAdded { id } }"}}`)
	maskedFrame := func(opcode byte, payload []byte) []byte {
		var b strings.Builder
		if err := writeWSFrame(&b, opcode, payload, true); err != nil {
			t.Fatal(err)
		}
		return []byte(b.String())
	}
	serverFrame := func(opcode byte) []byte {
		var b strings.Builder
		if err := writeWSFrame(&b, opcode, nil, false); err != nil {
			t.Fatal(err)
		}
		return []byte(b.String())
	}
	for _, tc := range []struct {
		name    string
		query   map[string][]string
		forward bool
	}{
		{name: "matching query", query: map[string][]string{"channel": {"updates"}}, forward: true},
		{name: "mismatched query", query: map[string][]string{"channel": {"admin"}}, forward: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientFrames := append(maskedFrame(wsOpcodeText, operation), maskedFrame(wsOpcodeClose, nil)...)
			var upstream strings.Builder
			var audit bytes.Buffer
			upReader, upWriter := io.Pipe()
			go func() {
				time.Sleep(10 * time.Millisecond)
				_, _ = upWriter.Write(serverFrame(wsOpcodeClose))
				_ = upWriter.Close()
			}()
			(&Server{audit: &audit}).relayWebsocket(context.Background(), bufio.NewReader(strings.NewReader(string(clientFrames))), io.Discard, bufio.NewReader(upReader), &upstream, "gql.example", 443, "/graphql", tc.query, eng, nil, nil, false, policy.ProtocolWebsocket, true, "", nil)
			forwarded := strings.Contains(upstream.String(), string(operation))
			if forwarded != tc.forward {
				t.Fatalf("forwarded operation=%v want=%v bytes=%x audit=%s", forwarded, tc.forward, upstream.String(), audit.String())
			}
		})
	}
}
