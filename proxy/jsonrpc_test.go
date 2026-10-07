package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whaleshell/whaleshell-core/engine"
	"github.com/whaleshell/whaleshell-core/policy"
)

func TestParseJSONRPCRequestValidatesAndExtractsBatchMethods(t *testing.T) {
	req := httptest.NewRequest("POST", "https://rpc.example.com", strings.NewReader(" \n [{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"chain_getBlock\"},{\"jsonrpc\":\"2.0\",\"method\":\"chain_getHead\"}] \n"))
	methods, err := parseJSONRPCRequest(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 2 || methods[0] != "chain_getBlock" || methods[1] != "chain_getHead" {
		t.Fatalf("methods=%v", methods)
	}
	forwarded, err := io.ReadAll(req.Body)
	if err != nil || len(forwarded) == 0 {
		t.Fatalf("request body was not restored: %q, %v", forwarded, err)
	}
}

func TestParseJSONRPCRequestRejectsMalformedMessages(t *testing.T) {
	for _, body := range []string{
		`[]`,
		`{"jsonrpc":"1.0","method":"x"}`,
		`{"jsonrpc":"2.0","id":1,"result":true}`,
		`{"jsonrpc":"2.0","method":"x","result":true}`,
		`{"jsonrpc":"2.0","method":1}`,
	} {
		req := httptest.NewRequest("POST", "https://rpc.example.com", strings.NewReader(body))
		if _, err := parseJSONRPCRequest(req, nil); err == nil {
			t.Fatalf("accepted malformed JSON-RPC message: %s", body)
		}
	}
}

func TestParseJSONRPCRequestKeepsGenericParamsCompatibility(t *testing.T) {
	req := httptest.NewRequest("POST", "https://rpc.example.com", strings.NewReader(`{"jsonrpc":"2.0","method":"x","params":"upstream accepts generic params"}`))
	methods, err := parseJSONRPCRequest(req, nil)
	if err != nil || len(methods) != 1 || methods[0] != "x" {
		t.Fatalf("methods=%v, err=%v", methods, err)
	}
}

func TestParseJSONRPCReceiveStreamRequiresSSEAccept(t *testing.T) {
	req := httptest.NewRequest("GET", "https://rpc.example.com", nil)
	if _, err := parseJSONRPCRequest(req, nil); err == nil {
		t.Fatal("GET without a JSON-RPC body or SSE Accept must fail closed")
	}
	req.Header.Set("Accept", "application/json, text/event-stream; charset=utf-8")
	methods, err := parseJSONRPCRequest(req, nil)
	if err != nil || len(methods) != 1 || methods[0] != http.MethodGet {
		t.Fatalf("receive stream methods=%v err=%v", methods, err)
	}
}

func TestParseJSONRPCRequestBodyLimit(t *testing.T) {
	limit := uint32(16)
	req := httptest.NewRequest("POST", "https://rpc.example.com", strings.NewReader(`{"jsonrpc":"2.0","method":"x"}`))
	if _, err := parseJSONRPCRequest(req, &policy.JSONRPCConfig{MaxBodyBytes: &limit}); err == nil || !strings.Contains(err.Error(), "exceeds 16 bytes") {
		t.Fatalf("body limit error=%v", err)
	}
}

func TestParseJSONRPCRequestNormalizesChunkedBody(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"chain_getBlock"}`
	req := httptest.NewRequest("POST", "https://rpc.example.com", strings.NewReader(body))
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1
	req.Header.Set("Transfer-Encoding", "chunked")
	if _, err := parseJSONRPCRequest(req, nil); err != nil {
		t.Fatal(err)
	}
	if len(req.TransferEncoding) != 0 || req.Header.Get("Transfer-Encoding") != "" || req.ContentLength != int64(len(body)) {
		t.Fatalf("framing wasn't normalized: transfer=%v header=%q length=%d", req.TransferEncoding, req.Header.Get("Transfer-Encoding"), req.ContentLength)
	}
}

func TestDecideJSONRPCChecksEveryMethodInBatch(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: "rpc.example.com", Port: 443, TLS: "terminate", Protocol: policy.ProtocolJSONRPC,
		Rules: []policy.L7Rule{{Allow: &policy.L7Allow{Method: "chain_getBlock"}}},
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	request := func(body string) *http.Request {
		req := httptest.NewRequest("POST", "https://rpc.example.com/rpc", strings.NewReader(body))
		req.RequestURI = "/rpc"
		return req
	}
	allowed, err := server.decideHTTP(request(`{"jsonrpc":"2.0","id":1,"method":"chain_getBlock"}`), eng, "rpc.example.com", 443, "/rpc", "")
	if err != nil || !allowed.Allow {
		t.Fatalf("single method decision=%+v, err=%v", allowed, err)
	}
	denied, err := server.decideHTTP(request(`[{"jsonrpc":"2.0","id":1,"method":"chain_getBlock"},{"jsonrpc":"2.0","method":"admin_drain"}]`), eng, "rpc.example.com", 443, "/rpc", "")
	if err != nil || denied.Allow {
		t.Fatalf("batch decision=%+v, err=%v; every method must be allowed", denied, err)
	}
}
