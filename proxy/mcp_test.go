package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cauteum-haven/cauteum-core/engine"
	"github.com/cauteum-haven/cauteum-core/policy"
)

func TestMCPMatchHTTP(t *testing.T) {
	rule := policy.AllowRule{
		Host: "mcp.example.com", Port: 443, Protocol: "mcp", TLS: "terminate",
		Rules: []policy.L7Rule{
			{Allow: &policy.L7Allow{Method: "tools/list"}},
			{Allow: &policy.L7Allow{Method: "tools/call", Tool: &policy.QueryMatcher{Any: []string{"safe_*"}}}},
		},
	}
	ok, _ := rule.MatchHTTP("tools/list", "/")
	if !ok {
		t.Fatal("tools/list")
	}
	ok, _ = rule.MatchHTTP("tools/call", "/\x00safe_read")
	if !ok {
		t.Fatal("tools/call safe_read")
	}
	ok, _ = rule.MatchHTTP("tools/call", "/\x00evil")
	if ok {
		t.Fatal("evil tool should deny")
	}
}

func TestParseMCPRequestConfig(t *testing.T) {
	strict := true
	nonStrict := false
	tests := []struct {
		name   string
		body   string
		config *policy.MCPConfig
		want   string
		fails  bool
	}{
		{name: "valid", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_read"}}`, config: &policy.MCPConfig{StrictToolNames: &strict}, want: "safe_read"},
		{name: "strict name", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bad name"}}`, config: &policy.MCPConfig{StrictToolNames: &strict}, fails: true},
		{name: "custom limit", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, config: &policy.MCPConfig{MaxBodyBytes: 8}, fails: true},
		{name: "strict disabled", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bad name"}}`, config: &policy.MCPConfig{StrictToolNames: &nonStrict}, want: "bad name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://mcp.example.com", strings.NewReader(tt.body))
			req.Header.Set("MCP-Protocol-Version", defaultMCPAllowedVersion)
			_, tool, err := parseMCPRequest(req, tt.config)
			if (err != nil) != tt.fails {
				t.Fatalf("err=%v, fails=%v", err, tt.fails)
			}
			if err == nil && tool != tt.want {
				t.Fatalf("tool=%q, want %q", tool, tt.want)
			}
		})
	}
}

func TestValidateMCPProtocolVersion(t *testing.T) {
	allowedLegacy := &policy.MCPConfig{Versions: []string{"2025-03-26"}}
	tests := []struct {
		name    string
		header  []string
		config  *policy.MCPConfig
		conn    string
		wantErr bool
	}{
		{name: "legacy fallback allowed", config: allowedLegacy},
		{name: "default rejects legacy fallback", config: &policy.MCPConfig{}, wantErr: true},
		{name: "exact allowed header", header: []string{"2025-06-18"}, config: &policy.MCPConfig{Versions: []string{"2025-06-18"}}},
		{name: "duplicate header", header: []string{"2025-03-26", "2025-06-18"}, config: allowedLegacy, wantErr: true},
		{name: "unsupported header", header: []string{"2024-01-01"}, config: allowedLegacy, wantErr: true},
		{name: "connection nominated", header: []string{"2025-03-26"}, config: allowedLegacy, conn: "MCP-Protocol-Version", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://mcp.example.com", nil)
			for _, value := range tt.header {
				req.Header.Add("MCP-Protocol-Version", value)
			}
			if tt.conn != "" {
				req.Header.Set("Connection", tt.conn)
			}
			err := validateMCPProtocolVersion(req, tt.config, "2.0", nil, "tools/list", nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestParseMCPInitializeNegotiatesInBody(t *testing.T) {
	req := httptest.NewRequest("POST", "https://mcp.example.com", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
	))
	// OpenShell exempts a standalone initialize request from the subsequent
	// request header allowlist; MCP initialization negotiates via the body.
	method, _, err := parseMCPRequest(req, &policy.MCPConfig{Versions: []string{"2025-03-26"}})
	if err != nil {
		t.Fatal(err)
	}
	if method != "initialize" {
		t.Fatalf("method=%q", method)
	}
}

func TestParseMCPMessagesValidatesBatchAndBootstrap(t *testing.T) {
	request := func(body string) *http.Request {
		req := httptest.NewRequest("POST", "https://mcp.example.com", strings.NewReader(body))
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		return req
	}
	messages, err := parseMCPMessages(request(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`), nil)
	if err != nil || len(messages) != 2 || messages[0].method != "tools/list" || messages[1].method != "notifications/initialized" {
		t.Fatalf("messages=%+v err=%v", messages, err)
	}
	for _, body := range []string{
		`[]`,
		`[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}},{"jsonrpc":"2.0","method":"tools/list"}]`,
		`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
		`{"jsonrpc":"2.0","method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"notifications/progress","params":{"progressToken":{},"progress":1}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":null}}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read"}`,
		`{"jsonrpc":"2.0","id":1,"method":"logging/setLevel"}`,
		`{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}`,
		`{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"message":"m","requestedSchema":null}}`,
	} {
		if _, err := parseMCPMessages(request(body), nil); err == nil {
			t.Fatalf("accepted invalid MCP message %s", body)
		}
	}
}

func TestParseMCPNotificationsValidateTypedParams(t *testing.T) {
	request := func(body string) *http.Request {
		req := httptest.NewRequest("POST", "https://mcp.example.com", strings.NewReader(body))
		req.Header.Set("MCP-Protocol-Version", defaultMCPAllowedVersion)
		return req
	}
	valid := []string{
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"req-1","reason":"cancelled"}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"req-1","progress":1,"total":2,"message":"working"}}`,
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"warning","data":{"message":"warning"},"logger":"agent"}}`,
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":null}}`,
		`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///workspace/readme.md"}}`,
		`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":""}}`,
		`{"jsonrpc":"2.0","method":"notifications/elicitation/complete","params":{"elicitationId":"flow-1"}}`,
		`{"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"task-1","status":"working","createdAt":"2026-01-01T00:00:00Z","lastUpdatedAt":"2026-01-01T00:00:01Z","ttl":1000,"pollInterval":100}}`,
	}
	for _, body := range valid {
		if _, err := parseMCPMessages(request(body), nil); err != nil {
			t.Errorf("rejected valid MCP notification %s: %v", body, err)
		}
	}
	invalid := []string{
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":null}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"req-1","reason":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":{},"progress":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":"one"}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1.5,"progress":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"verbose","data":"x"}}`,
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`,
		`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":false}}`,
		`{"jsonrpc":"2.0","method":"notifications/elicitation/complete","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"task-1","status":"unknown","createdAt":"now","lastUpdatedAt":"now"}}`,
		`{"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"task-1","status":"working","createdAt":"now","lastUpdatedAt":"now","ttl":-1}}`,
	}
	for _, body := range invalid {
		if _, err := parseMCPMessages(request(body), nil); err == nil {
			t.Errorf("accepted invalid MCP notification %s", body)
		}
	}
}

func TestParseMCPTypedSamplingCompletionAndElicitationParams(t *testing.T) {
	request := func(body string) *http.Request {
		req := httptest.NewRequest("POST", "https://mcp.example.com", strings.NewReader(body))
		req.Header.Set("MCP-Protocol-Version", defaultMCPAllowedVersion)
		return req
	}
	valid := []string{
		`{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"},"argument":{"name":"q","value":""}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///p/{q}"},"argument":{"name":"q","value":"par"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"},"argument":{"name":"q","value":"par"},"context":{"arguments":{"language":"go"}}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"p","arguments":{"language":"go"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"async","arguments":{},"task":{"ttl":30000}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/list","params":{"status":"working","cursor":"page-2"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"taskId":"task-1"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/result","params":{"taskId":"task-1"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/cancel","params":{"taskId":"task-1","reason":"stop"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/update","params":{"taskId":"task-1","inputResponses":{"request-1":{"action":"accept"}}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"assistant","content":[{"type":"text","text":"hi"},{"type":"image","data":"AA==","mimeType":"image/png"}]}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":0,"systemPrompt":"You are helpful","includeContext":"thisServer","temperature":0.4,"stopSequences":["END"],"metadata":{"trace":"x"},"modelPreferences":{"hints":[{"name":"small"}],"costPriority":0.2,"speedPriority":0.5,"intelligencePriority":1},"toolChoice":{"mode":"auto"},"tools":[{"name":"lookup","inputSchema":{"type":"object"}}]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi","annotations":{"audience":["user"],"priority":0.5,"lastModified":"2026-01-01T00:00:00Z"}}}],"maxTokens":8,"task":{"ttl":30000},"toolChoice":{"mode":"tool","name":"lookup"},"tools":[{"name":"lookup","title":"Lookup","description":"Find records","inputSchema":{"type":"object"},"outputSchema":{"type":"object"},"icons":[{"src":"https://example.com/icon.svg","mimeType":"image/svg+xml","sizes":["48x48"],"theme":"light"}],"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false},"execution":{"taskSupport":"optional"}}],"_meta":{"trace":"x"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"call-1","name":"lookup","input":{"q":"x"}},{"type":"tool_result","toolUseId":"call-1","content":[{"type":"text","text":"found"}],"structuredContent":{"count":1},"isError":false}]}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"form","message":"Name?","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"url","message":"Authorize","url":"https://auth.example.com/","elicitationId":"flow-1"}}`,
	}
	for _, body := range valid {
		if _, err := parseMCPMessages(request(body), nil); err != nil {
			t.Errorf("rejected valid MCP request %s: %v", body, err)
		}
	}
	invalid := []string{
		`{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"},"argument":{"name":"q"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p"},"argument":{"name":"q","value":"par"},"context":{"arguments":{"language":1}}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"p","arguments":{"language":1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"p","arguments":[]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"async","task":{"ttl":-1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/list","params":{"status":"queued"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/result","params":{"taskId":1}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/cancel","params":{"taskId":"task-1","reason":1}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/update","params":{"taskId":"task-1","inputResponses":[]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"system","content":{"type":"text","text":"hi"}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text"}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"resource","uri":"x"}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":null}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":-1}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"includeContext":"server"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"modelPreferences":{"costPriority":1.2}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi","annotations":{"audience":["server"]}}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"tools":[{"name":"lookup","inputSchema":{"type":"object"},"icons":[{"src":"icon","theme":"sepia"}]}]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"tools":[{"name":"lookup","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":"yes"}}]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"tools":[{"name":"lookup","inputSchema":{"type":"object"},"execution":{"taskSupport":"sometimes"}}]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"tools":[{"name":"lookup","inputSchema":[]}]}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"assistant","content":{"type":"tool_use","id":"call-1","name":"lookup","input":[]}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"assistant","content":{"type":"tool_result","toolUseId":"call-1","content":[{"type":"text"}]}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"task":{"ttl":-1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":10,"toolChoice":{"mode":1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"assistant","content":{"type":"tool_result","toolUseId":"call-2","content":[{"type":"resource","resource":{"uri":false}}]}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"assistant","content":{"type":"tool_result","toolUseId":"call-2","content":[{"type":"resource_link","uri":"file:///result.json","name":"result"}]}}],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"form","message":"Name?"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"url","message":"Authorize","url":"https://auth.example.com/"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"other","message":"Name?","requestedSchema":{"type":"object"}}}`,
	}
	for _, body := range invalid {
		if _, err := parseMCPMessages(request(body), nil); err == nil {
			t.Errorf("accepted invalid MCP request %s", body)
		}
	}
}

func TestParseMCPMessagesAcceptsValidResponseFrames(t *testing.T) {
	req := httptest.NewRequest("POST", "https://mcp.example.com", strings.NewReader(`{"jsonrpc":"2.0","id":"server-call","result":{"accepted":true}}`))
	req.Header.Set("MCP-Protocol-Version", defaultMCPAllowedVersion)
	messages, err := parseMCPMessages(req, nil)
	if err != nil || len(messages) != 1 || !messages[0].response {
		t.Fatalf("messages=%+v err=%v", messages, err)
	}
}

func TestParseMCPMessagesValidatesPinnedResponseTypes(t *testing.T) {
	parse := func(body string) error {
		req := httptest.NewRequest("POST", "https://mcp.example.com", strings.NewReader(body))
		req.Header.Set("MCP-Protocol-Version", defaultMCPAllowedVersion)
		_, err := parseMCPMessages(req, nil)
		return err
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":7,"result":null}`,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid request"}}`,
		`{"jsonrpc":"2.0","id":"x","error":{"code":1,"message":"","data":{"detail":"bad"}}}`,
	} {
		if err := parse(body); err != nil {
			t.Errorf("rejected valid JSON-RPC response %s: %v", body, err)
		}
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":null,"result":{}}`,
		`{"jsonrpc":"2.0","id":1.5,"result":{}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600.5,"message":"invalid"}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":false}}`,
		`{"jsonrpc":"2.0","error":{"code":-32600,"message":"invalid"}}`,
	} {
		if err := parse(body); err == nil {
			t.Errorf("accepted invalid JSON-RPC response %s", body)
		}
	}
}

func TestParseMCPReceiveStreamRequiresSSEAndAllowedVersion(t *testing.T) {
	config := &policy.MCPConfig{Versions: []string{"2025-11-25"}}
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	req.Header.Set("Accept", "application/json, text/event-stream; charset=utf-8")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	messages, err := parseMCPMessages(req, config)
	if err != nil || len(messages) != 1 || !messages[0].receiveStream {
		t.Fatalf("messages=%+v err=%v", messages, err)
	}
	withoutSSE := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	withoutSSE.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if _, err := parseMCPMessages(withoutSSE, config); err == nil {
		t.Fatal("GET without SSE Accept must be denied")
	}
	wrongVersion := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	wrongVersion.Header.Set("Accept", "text/event-stream")
	wrongVersion.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if _, err := parseMCPMessages(wrongVersion, config); err == nil {
		t.Fatal("receive stream with a disallowed protocol version must be denied")
	}
}

func TestDecideMCPChecksEveryBatchCallAndAllowsResponses(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: "mcp.example.com", Port: 443, TLS: policy.TLSTerminate, Protocol: policy.ProtocolMCP,
		MCP: &policy.MCPConfig{Versions: []string{"2025-11-25"}},
		Rules: []policy.L7Rule{
			{Allow: &policy.L7Allow{Method: "tools/list"}},
			{Allow: &policy.L7Allow{Method: "notifications/initialized"}},
		},
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	decide := func(body string) (engine.Decision, error) {
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", strings.NewReader(body))
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		req.RequestURI = "/mcp"
		return server.decideHTTP(req, eng, "mcp.example.com", 443, "/mcp", "")
	}
	allowed, err := decide(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`)
	if err != nil || !allowed.Allow {
		t.Fatalf("batch decision=%+v err=%v", allowed, err)
	}
	denied, err := decide(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unsafe"}}]`)
	if err != nil || denied.Allow {
		t.Fatalf("disallowed batch decision=%+v err=%v", denied, err)
	}
	response, err := decide(`{"jsonrpc":"2.0","id":"server-1","result":{"ok":true}}`)
	if err != nil || !response.Allow {
		t.Fatalf("MCP response decision=%+v err=%v", response, err)
	}
}

func TestDecideMCPAllowsAuthorizedSSEReceiveStream(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		Host: "mcp.example.com", Port: 443, TLS: policy.TLSTerminate, Protocol: policy.ProtocolMCP,
		MCP:   &policy.MCPConfig{Versions: []string{"2025-11-25"}},
		Rules: []policy.L7Rule{{Allow: &policy.L7Allow{Method: "tools/list"}}},
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.RequestURI = "/mcp"
	decision, err := (&Server{}).decideHTTP(req, eng, "mcp.example.com", 443, "/mcp", "")
	if err != nil || !decision.Allow {
		t.Fatalf("receive stream decision=%+v err=%v", decision, err)
	}
}

func TestMCPAnyToolSelectorChecksBatch(t *testing.T) {
	doc, err := policy.Parse([]byte(`version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        rules:
          - allow:
              method: tools/call
              params:
                name: {any: ["safe_*", "read_{repo,file}"]}
        deny_rules:
          - method: tools/call
            tool: {any: [safe_delete]}
`))
	if err != nil {
		t.Fatal(err)
	}
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_repo"}}`, true},
		{`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_read"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"safe_delete"}}]`, false},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unlisted"}}`, false},
	} {
		req := httptest.NewRequest("POST", "https://mcp.example.com/mcp", strings.NewReader(tc.body))
		req.RequestURI = "/mcp"
		req.Header.Set("MCP-Protocol-Version", defaultMCPAllowedVersion)
		decision, err := server.decideHTTP(req, eng, "mcp.example.com", 443, "/mcp", "")
		if err != nil || decision.Allow != tc.want {
			t.Fatalf("body=%s decision=%+v err=%v", tc.body, decision, err)
		}
	}
}
