package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/cautem/cautem-core/policy"
)

// parseMCPRequest extracts JSON-RPC method and optional tools/call name from an HTTP body.
// Returns method, tool, restored body reader, error. Fail-closed on invalid JSON for MCP.
const defaultMCPMaxBodyBytes = 64 << 10

var mcpToolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func parseMCPRequest(req *http.Request, config *policy.MCPConfig) (method, tool string, err error) {
	messages, err := parseMCPMessages(req, config)
	if err != nil {
		return "", "", err
	}
	if len(messages) != 1 || messages[0].response {
		return "", "", fmt.Errorf("mcp: expected one request message")
	}
	return messages[0].method, messages[0].tool, nil
}

type mcpMessage struct {
	method        string
	tool          string
	response      bool
	receiveStream bool
}

func parseMCPMessages(req *http.Request, config *policy.MCPConfig) ([]mcpMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("mcp: missing request")
	}
	noBody := req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0
	if strings.EqualFold(req.Method, http.MethodGet) && noBody && requestAcceptsJSONRPCStream(req) {
		if err := validateMCPProtocolVersion(req, config, "2.0", nil, "", nil); err != nil {
			return nil, err
		}
		return []mcpMessage{{receiveStream: true}}, nil
	}
	if req.Body == nil {
		return nil, fmt.Errorf("mcp: empty body")
	}
	maxBytes := uint32(defaultMCPMaxBodyBytes)
	strictToolNames := true
	if config != nil {
		if config.MaxBodyBytes > 0 {
			maxBytes = config.MaxBodyBytes
		}
		if config.StrictToolNames != nil {
			strictToolNames = *config.StrictToolNames
		}
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, int64(maxBytes)+1))
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.Header.Del("Transfer-Encoding")
	if uint64(len(body)) > uint64(maxBytes) {
		return nil, fmt.Errorf("mcp: request body exceeds %d bytes", maxBytes)
	}
	var payload json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("mcp: invalid json-rpc: %w", err)
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return nil, fmt.Errorf("mcp: empty JSON-RPC message")
	}
	items := []json.RawMessage{payload}
	batched := payload[0] == '['
	if batched {
		if err := json.Unmarshal(payload, &items); err != nil || len(items) == 0 {
			return nil, fmt.Errorf("mcp: batch must be a non-empty array")
		}
	}
	messages := make([]mcpMessage, 0, len(items))
	for _, item := range items {
		var object map[string]json.RawMessage
		if len(item) == 0 || item[0] != '{' || json.Unmarshal(item, &object) != nil {
			return nil, fmt.Errorf("mcp: batch item must be an object")
		}
		var version string
		if json.Unmarshal(object["jsonrpc"], &version) != nil || version != "2.0" {
			return nil, fmt.Errorf("mcp: jsonrpc must be \"2.0\"")
		}
		if rawMethod, exists := object["method"]; exists {
			var method string
			if json.Unmarshal(rawMethod, &method) != nil || strings.TrimSpace(method) == "" {
				return nil, fmt.Errorf("mcp: method must be a non-empty string")
			}
			_, hasID := object["id"]
			if strings.HasPrefix(method, "notifications/") {
				if hasID {
					return nil, fmt.Errorf("mcp: notification must not contain an id")
				}
			} else if err := validateMCPRequestID(object["id"], hasID); err != nil {
				return nil, err
			}
			if _, result := object["result"]; result {
				return nil, fmt.Errorf("mcp: request cannot contain result")
			}
			if _, rpcError := object["error"]; rpcError {
				return nil, fmt.Errorf("mcp: request cannot contain error")
			}
			if batched && method == "initialize" {
				return nil, fmt.Errorf("mcp: initialize must not appear in a batch")
			}
			var params struct {
				Name            string `json:"name"`
				ProtocolVersion string `json:"protocolVersion"`
			}
			var paramPointer *struct {
				Name            string `json:"name"`
				ProtocolVersion string `json:"protocolVersion"`
			}
			if rawParams, ok := object["params"]; ok && string(rawParams) != "null" {
				if rawParams[0] != '{' || json.Unmarshal(rawParams, &params) != nil {
					return nil, fmt.Errorf("mcp: params must be an object")
				}
				paramPointer = &params
			}
			if err := validateMCPMethodParams(method, paramPointer, object["params"]); err != nil {
				return nil, err
			}
			tool := ""
			if method == "tools/call" {
				if paramPointer == nil || params.Name == "" {
					return nil, fmt.Errorf("mcp: tools/call requires params.name")
				}
				tool = params.Name
				if strictToolNames && !mcpToolName.MatchString(tool) {
					return nil, fmt.Errorf("mcp: invalid tool name")
				}
			}
			if method == "initialize" && paramPointer != nil {
				if _, supported := supportedMCPVersions[params.ProtocolVersion]; !supported {
					return nil, fmt.Errorf("mcp: unsupported initialize protocol version %q", params.ProtocolVersion)
				}
			}
			if method == "initialize" {
				var clientInfo struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}
				var initParams map[string]json.RawMessage
				var capabilities map[string]json.RawMessage
				rawParams, hasParams := object["params"]
				if !hasParams || json.Unmarshal(rawParams, &initParams) != nil || initParams == nil || paramPointer == nil ||
					params.ProtocolVersion == "" || json.Unmarshal(initParams["capabilities"], &capabilities) != nil || capabilities == nil ||
					json.Unmarshal(initParams["clientInfo"], &clientInfo) != nil || clientInfo.Name == "" || clientInfo.Version == "" {
					return nil, fmt.Errorf("mcp: initialize requires protocolVersion, capabilities, and clientInfo")
				}
			}
			if err := validateMCPProtocolVersion(req, config, version, rawJSONPointer(object, "id"), method, paramPointer); err != nil {
				return nil, err
			}
			messages = append(messages, mcpMessage{method: method, tool: tool})
			continue
		}
		if _, result := object["result"]; result {
			if _, rpcError := object["error"]; rpcError {
				return nil, fmt.Errorf("mcp: response cannot contain both result and error")
			}
			if err := validateMCPResponseID(object["id"], false); err != nil {
				return nil, err
			}
			if err := validateMCPProtocolVersion(req, config, version, nil, "", nil); err != nil {
				return nil, err
			}
			messages = append(messages, mcpMessage{response: true})
			continue
		}
		if _, rpcError := object["error"]; rpcError {
			if err := validateMCPResponseID(object["id"], true); err != nil {
				return nil, err
			}
			var errorFields map[string]json.RawMessage
			var code int32
			var message string
			if json.Unmarshal(object["error"], &errorFields) != nil || errorFields == nil ||
				len(errorFields["code"]) == 0 || isJSONNull(errorFields["code"]) || json.Unmarshal(errorFields["code"], &code) != nil ||
				len(errorFields["message"]) == 0 || isJSONNull(errorFields["message"]) || json.Unmarshal(errorFields["message"], &message) != nil {
				return nil, fmt.Errorf("mcp: response error requires int32 code and string message")
			}
			if err := validateMCPProtocolVersion(req, config, version, nil, "", nil); err != nil {
				return nil, err
			}
			messages = append(messages, mcpMessage{response: true})
			continue
		}
		return nil, fmt.Errorf("mcp: message requires method or response")
	}
	return messages, nil
}

func validateMCPRequestID(raw json.RawMessage, present bool) error {
	if !present {
		return fmt.Errorf("mcp: request method requires an id")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return fmt.Errorf("mcp: invalid request id")
	}
	switch value := value.(type) {
	case string:
		return nil
	case json.Number:
		if _, err := strconv.ParseInt(string(value), 10, 64); err == nil {
			return nil
		}
		return fmt.Errorf("mcp: request id number must be a signed integer")
	default:
		return fmt.Errorf("mcp: request id must be a string or signed integer")
	}
}

func validateMCPMethodParams(method string, params *struct {
	Name            string `json:"name"`
	ProtocolVersion string `json:"protocolVersion"`
}, raw json.RawMessage) error {
	if strings.HasPrefix(method, "notifications/") {
		if method == "notifications/cancelled" {
			var value struct {
				RequestID json.RawMessage `json:"requestId"`
				Reason    *string         `json:"reason"`
			}
			if json.Unmarshal(raw, &value) != nil || validateMCPRequestID(value.RequestID, len(value.RequestID) > 0) != nil {
				return fmt.Errorf("mcp: notifications/cancelled requires params.requestId")
			}
		}
		if method == "notifications/progress" {
			var value struct {
				Token    json.RawMessage `json:"progressToken"`
				Progress *float64        `json:"progress"`
				Total    *float64        `json:"total"`
				Message  *string         `json:"message"`
			}
			if json.Unmarshal(raw, &value) != nil || len(value.Token) == 0 || value.Progress == nil {
				return fmt.Errorf("mcp: notifications/progress requires progressToken and progress")
			}
			if err := validateMCPRequestID(value.Token, true); err != nil {
				return fmt.Errorf("mcp: notifications/progress progressToken must be a string or signed integer")
			}
		}
		if method == "notifications/message" {
			var value struct {
				Level  string          `json:"level"`
				Logger *string         `json:"logger"`
				Data   json.RawMessage `json:"data"`
			}
			if json.Unmarshal(raw, &value) != nil || len(value.Data) == 0 ||
				!map[string]bool{
					"debug": true, "info": true, "notice": true, "warning": true,
					"error": true, "critical": true, "alert": true, "emergency": true,
				}[value.Level] {
				return fmt.Errorf("mcp: notifications/message requires a valid level and data")
			}
		}
		if method == "notifications/resources/updated" {
			var value struct {
				URI json.RawMessage `json:"uri"`
			}
			var uri string
			if json.Unmarshal(raw, &value) != nil || len(value.URI) == 0 || json.Unmarshal(value.URI, &uri) != nil {
				return fmt.Errorf("mcp: notifications/resources/updated requires params.uri")
			}
		}
		if method == "notifications/elicitation/complete" {
			var value struct {
				ElicitationID string `json:"elicitationId"`
			}
			if json.Unmarshal(raw, &value) != nil || value.ElicitationID == "" {
				return fmt.Errorf("mcp: notifications/elicitation/complete requires elicitationId")
			}
		}
		if method == "notifications/tasks/status" {
			var value struct {
				TaskID        string  `json:"taskId"`
				Status        string  `json:"status"`
				CreatedAt     string  `json:"createdAt"`
				LastUpdatedAt string  `json:"lastUpdatedAt"`
				TTL           *uint64 `json:"ttl"`
				StatusMessage *string `json:"statusMessage"`
				PollInterval  *uint64 `json:"pollInterval"`
			}
			if json.Unmarshal(raw, &value) != nil || value.TaskID == "" || value.CreatedAt == "" || value.LastUpdatedAt == "" ||
				!map[string]bool{"working": true, "input_required": true, "completed": true, "failed": true, "cancelled": true}[value.Status] {
				return fmt.Errorf("mcp: notifications/tasks/status has invalid task status params")
			}
		}
		return nil
	}
	if method == "initialize" {
		return nil // Full required fields and version are checked below.
	}
	if method == "tools/call" {
		if params == nil || params.Name == "" {
			return fmt.Errorf("mcp: tools/call requires params.name")
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return fmt.Errorf("mcp: tools/call params must be an object")
		}
		if arguments, ok := object["arguments"]; ok {
			var args map[string]json.RawMessage
			if json.Unmarshal(arguments, &args) != nil || args == nil {
				return fmt.Errorf("mcp: tools/call params.arguments must be an object")
			}
		}
		if task, ok := object["task"]; ok && !isJSONNull(task) {
			if err := validateMCPTaskParams(task); err != nil {
				return err
			}
		}
		return nil
	}
	requiredField := map[string]string{
		"resources/read": "uri", "resources/subscribe": "uri", "resources/unsubscribe": "uri", "prompts/get": "name",
		"tasks/get": "taskId", "tasks/result": "taskId", "tasks/cancel": "taskId", "tasks/update": "taskId",
	}[method]
	requiresObject := requiredField != "" || method == "logging/setLevel" || method == "completion/complete" ||
		method == "sampling/createMessage" || method == "elicitation/create"
	if raw == nil || string(raw) == "null" {
		if requiresObject {
			return fmt.Errorf("mcp: %s requires an object params", method)
		}
		return nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return fmt.Errorf("mcp: params must be an object")
	}
	for _, key := range []string{"cursor", "uri", "name", "level", "taskId"} {
		if value, ok := object[key]; ok {
			var text string
			if json.Unmarshal(value, &text) != nil || text == "" {
				return fmt.Errorf("mcp: params.%s must be a non-empty string", key)
			}
		}
	}
	if requiredField != "" {
		if _, ok := object[requiredField]; !ok {
			return fmt.Errorf("mcp: %s requires params.%s", method, requiredField)
		}
	}
	if method == "logging/setLevel" {
		var level string
		if json.Unmarshal(object["level"], &level) != nil || !map[string]bool{
			"debug": true, "info": true, "notice": true, "warning": true, "error": true, "critical": true, "alert": true, "emergency": true,
		}[level] {
			return fmt.Errorf("mcp: logging/setLevel has invalid params.level")
		}
	}
	if method == "tasks/list" {
		if status, ok := object["status"]; ok && !isJSONNull(status) {
			var value string
			if json.Unmarshal(status, &value) != nil || !isMapValue(value, "working", "input_required", "completed", "failed", "cancelled") {
				return fmt.Errorf("mcp: tasks/list has invalid params.status")
			}
		}
	}
	if method == "tasks/cancel" {
		if reason, ok := object["reason"]; ok && !isJSONNull(reason) {
			var value string
			if json.Unmarshal(reason, &value) != nil {
				return fmt.Errorf("mcp: tasks/cancel params.reason must be a string")
			}
		}
	}
	if method == "tasks/update" {
		if responses, ok := object["inputResponses"]; ok {
			var values map[string]json.RawMessage
			if json.Unmarshal(responses, &values) != nil || values == nil {
				return fmt.Errorf("mcp: tasks/update params.inputResponses must be an object")
			}
		}
	}
	if method == "completion/complete" {
		var completion map[string]json.RawMessage
		if json.Unmarshal(raw, &completion) != nil || completion == nil {
			return fmt.Errorf("mcp: completion/complete requires ref and argument")
		}
		var ref struct {
			Type string          `json:"type"`
			Name json.RawMessage `json:"name"`
			URI  json.RawMessage `json:"uri"`
		}
		var argument struct {
			Name  json.RawMessage `json:"name"`
			Value json.RawMessage `json:"value"`
		}
		if json.Unmarshal(completion["ref"], &ref) != nil || json.Unmarshal(completion["argument"], &argument) != nil {
			return fmt.Errorf("mcp: completion/complete requires ref and argument")
		}
		var name, value string
		if ref.Type == "ref/prompt" && json.Unmarshal(ref.Name, &name) != nil ||
			ref.Type == "ref/resource" && json.Unmarshal(ref.URI, &name) != nil ||
			ref.Type != "ref/prompt" && ref.Type != "ref/resource" ||
			json.Unmarshal(argument.Name, &name) != nil || json.Unmarshal(argument.Value, &value) != nil {
			return fmt.Errorf("mcp: completion/complete has invalid ref")
		}
		if contextRaw, ok := completion["context"]; ok && string(contextRaw) != "null" {
			var context map[string]json.RawMessage
			if json.Unmarshal(contextRaw, &context) != nil || context == nil {
				return fmt.Errorf("mcp: completion/complete context must be an object")
			}
			if arguments, ok := context["arguments"]; ok && string(arguments) != "null" {
				if err := validateMCPStringMap(arguments, "completion context arguments"); err != nil {
					return err
				}
			}
		}
	}
	if method == "prompts/get" {
		var prompt map[string]json.RawMessage
		if json.Unmarshal(raw, &prompt) != nil || prompt == nil {
			return fmt.Errorf("mcp: prompts/get params must be an object")
		}
		if arguments, ok := prompt["arguments"]; ok && string(arguments) != "null" {
			if err := validateMCPStringMap(arguments, "prompts/get arguments"); err != nil {
				return err
			}
		}
	}
	if method == "sampling/createMessage" {
		var sampling struct {
			Messages  []json.RawMessage `json:"messages"`
			MaxTokens uint32            `json:"maxTokens"`
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields["maxTokens"]) == 0 || isJSONNull(fields["maxTokens"]) ||
			json.Unmarshal(raw, &sampling) != nil || len(sampling.Messages) == 0 {
			return fmt.Errorf("mcp: sampling/createMessage requires messages and maxTokens")
		}
		for _, message := range sampling.Messages {
			if err := validateMCPSamplingMessage(message); err != nil {
				return err
			}
		}
		if err := validateMCPSamplingOptions(raw); err != nil {
			return err
		}
	}
	if method == "elicitation/create" {
		var elicitation struct {
			Mode            string          `json:"mode"`
			Message         string          `json:"message"`
			RequestedSchema json.RawMessage `json:"requestedSchema"`
			URL             json.RawMessage `json:"url"`
			ElicitationID   json.RawMessage `json:"elicitationId"`
		}
		if json.Unmarshal(raw, &elicitation) != nil || strings.TrimSpace(elicitation.Message) == "" {
			return fmt.Errorf("mcp: elicitation/create requires message")
		}
		switch elicitation.Mode {
		case "", "form":
			var schema map[string]json.RawMessage
			if json.Unmarshal(elicitation.RequestedSchema, &schema) != nil || schema == nil {
				return fmt.Errorf("mcp: form elicitation requires requestedSchema object")
			}
		case "url":
			var target, id string
			if json.Unmarshal(elicitation.URL, &target) != nil || target == "" ||
				json.Unmarshal(elicitation.ElicitationID, &id) != nil || id == "" {
				return fmt.Errorf("mcp: URL elicitation requires url and elicitationId")
			}
		default:
			return fmt.Errorf("mcp: elicitation/create has invalid mode")
		}
	}
	return nil
}

func validateMCPSamplingOptions(raw json.RawMessage) error {
	var params map[string]json.RawMessage
	if json.Unmarshal(raw, &params) != nil || params == nil {
		return fmt.Errorf("mcp: sampling/createMessage params must be an object")
	}
	if value, ok := params["systemPrompt"]; ok && !isJSONNull(value) {
		var prompt string
		if json.Unmarshal(value, &prompt) != nil {
			return fmt.Errorf("mcp: sampling systemPrompt must be a string")
		}
	}
	if value, ok := params["includeContext"]; ok && !isJSONNull(value) {
		var context string
		if json.Unmarshal(value, &context) != nil ||
			context != "none" && context != "thisServer" && context != "allServers" {
			return fmt.Errorf("mcp: sampling includeContext has an invalid value")
		}
	}
	if value, ok := params["temperature"]; ok && !isJSONNull(value) {
		var temperature float64
		if json.Unmarshal(value, &temperature) != nil {
			return fmt.Errorf("mcp: sampling temperature must be a number")
		}
	}
	if value, ok := params["stopSequences"]; ok && !isJSONNull(value) {
		var sequences []string
		if json.Unmarshal(value, &sequences) != nil || sequences == nil {
			return fmt.Errorf("mcp: sampling stopSequences must be an array of strings")
		}
	} else if value, ok := params["stopSequences"]; ok && isJSONNull(value) {
		return fmt.Errorf("mcp: sampling stopSequences must be an array of strings")
	}
	if value, ok := params["metadata"]; ok && !isJSONNull(value) {
		var metadata map[string]json.RawMessage
		if json.Unmarshal(value, &metadata) != nil || metadata == nil {
			return fmt.Errorf("mcp: sampling metadata must be an object")
		}
	}
	if value, ok := params["modelPreferences"]; ok && !isJSONNull(value) {
		if err := validateMCPModelPreferences(value); err != nil {
			return err
		}
	}
	if value, ok := params["toolChoice"]; ok && !isJSONNull(value) {
		var choice struct {
			Mode *string `json:"mode"`
			Name *string `json:"name"`
		}
		if json.Unmarshal(value, &choice) != nil || choice.Mode == nil {
			return fmt.Errorf("mcp: sampling toolChoice requires a mode string")
		}
	}
	if value, ok := params["tools"]; ok && !isJSONNull(value) {
		var tools []map[string]json.RawMessage
		if json.Unmarshal(value, &tools) != nil || tools == nil {
			return fmt.Errorf("mcp: sampling tools must be an array of tool objects")
		}
		for i, tool := range tools {
			var name string
			var inputSchema map[string]json.RawMessage
			if json.Unmarshal(tool["name"], &name) != nil ||
				json.Unmarshal(tool["inputSchema"], &inputSchema) != nil || inputSchema == nil {
				return fmt.Errorf("mcp: sampling tools[%d] requires name and inputSchema object", i)
			}
			for _, key := range []string{"title", "description"} {
				if field, ok := tool[key]; ok && !isJSONNull(field) {
					var text string
					if json.Unmarshal(field, &text) != nil {
						return fmt.Errorf("mcp: sampling tools[%d].%s must be a string", i, key)
					}
				}
			}
			if icons, ok := tool["icons"]; ok && !isJSONNull(icons) {
				if err := validateMCPToolIcons(icons); err != nil {
					return fmt.Errorf("mcp: sampling tools[%d].icons: %w", i, err)
				}
			}
			if annotations, ok := tool["annotations"]; ok && !isJSONNull(annotations) {
				if err := validateMCPToolAnnotations(annotations); err != nil {
					return fmt.Errorf("mcp: sampling tools[%d].annotations: %w", i, err)
				}
			}
			if execution, ok := tool["execution"]; ok && !isJSONNull(execution) {
				var fields map[string]json.RawMessage
				if json.Unmarshal(execution, &fields) != nil || fields == nil {
					return fmt.Errorf("mcp: sampling tools[%d].execution must be an object", i)
				}
				if support, ok := fields["taskSupport"]; ok && !isJSONNull(support) {
					var value string
					if json.Unmarshal(support, &value) != nil || value != "required" && value != "optional" && value != "forbidden" {
						return fmt.Errorf("mcp: sampling tools[%d].execution.taskSupport is invalid", i)
					}
				}
			}
		}
	}
	if value, ok := params["task"]; ok && !isJSONNull(value) {
		if err := validateMCPTaskParams(value); err != nil {
			return fmt.Errorf("mcp: sampling %w", err)
		}
	}
	return nil
}

func validateMCPModelPreferences(raw json.RawMessage) error {
	var prefs map[string]json.RawMessage
	if json.Unmarshal(raw, &prefs) != nil || prefs == nil {
		return fmt.Errorf("mcp: modelPreferences must be an object")
	}
	if value, ok := prefs["hints"]; ok && !isJSONNull(value) {
		var hints []map[string]json.RawMessage
		if json.Unmarshal(value, &hints) != nil || hints == nil {
			return fmt.Errorf("mcp: modelPreferences hints must be an array of objects")
		}
		for i, hint := range hints {
			if name, ok := hint["name"]; ok && !isJSONNull(name) {
				var text string
				if json.Unmarshal(name, &text) != nil {
					return fmt.Errorf("mcp: modelPreferences hints[%d].name must be a string", i)
				}
			}
		}
	} else if value, ok := prefs["hints"]; ok && isJSONNull(value) {
		return fmt.Errorf("mcp: modelPreferences hints must be an array of objects")
	}
	for _, key := range []string{"costPriority", "speedPriority", "intelligencePriority"} {
		value, ok := prefs[key]
		if !ok || isJSONNull(value) {
			continue
		}
		var priority float64
		if json.Unmarshal(value, &priority) != nil || priority < 0 || priority > 1 {
			return fmt.Errorf("mcp: modelPreferences.%s must be a number from 0 to 1", key)
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateMCPToolIcons(raw json.RawMessage) error {
	var icons []map[string]json.RawMessage
	if json.Unmarshal(raw, &icons) != nil || icons == nil {
		return fmt.Errorf("must be an array")
	}
	for i, icon := range icons {
		var source string
		if json.Unmarshal(icon["src"], &source) != nil {
			return fmt.Errorf("item %d requires src string", i)
		}
		for _, key := range []string{"mimeType", "theme"} {
			if value, ok := icon[key]; ok && !isJSONNull(value) {
				var text string
				if json.Unmarshal(value, &text) != nil || key == "theme" && text != "light" && text != "dark" {
					return fmt.Errorf("item %d has invalid %s", i, key)
				}
			}
		}
		if sizes, ok := icon["sizes"]; ok && !isJSONNull(sizes) {
			var values []string
			if json.Unmarshal(sizes, &values) != nil || values == nil {
				return fmt.Errorf("item %d sizes must be an array of strings", i)
			}
		}
	}
	return nil
}

func validateMCPToolAnnotations(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return fmt.Errorf("must be an object")
	}
	if title, ok := fields["title"]; ok && !isJSONNull(title) {
		var value string
		if json.Unmarshal(title, &value) != nil {
			return fmt.Errorf("title must be a string")
		}
	}
	for _, key := range []string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
		if value, ok := fields[key]; ok {
			var flag bool
			if isJSONNull(value) || json.Unmarshal(value, &flag) != nil {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	return nil
}

func validateMCPContentAnnotations(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return fmt.Errorf("mcp: content annotations must be an object")
	}
	if audience, ok := fields["audience"]; ok && !isJSONNull(audience) {
		var roles []string
		if json.Unmarshal(audience, &roles) != nil || roles == nil {
			return fmt.Errorf("mcp: content annotations audience must be an array")
		}
		for _, role := range roles {
			if role != "user" && role != "assistant" {
				return fmt.Errorf("mcp: content annotations audience has an invalid role")
			}
		}
	}
	if priority, ok := fields["priority"]; ok && !isJSONNull(priority) {
		var value float64
		if json.Unmarshal(priority, &value) != nil {
			return fmt.Errorf("mcp: content annotations priority must be numeric")
		}
	}
	if modified, ok := fields["lastModified"]; ok && !isJSONNull(modified) {
		var value string
		if json.Unmarshal(modified, &value) != nil {
			return fmt.Errorf("mcp: content annotations lastModified must be a string")
		}
	}
	return nil
}

func validateMCPStringMap(raw json.RawMessage, field string) error {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return fmt.Errorf("mcp: %s must be an object of strings", field)
	}
	for key, value := range values {
		var text string
		if json.Unmarshal(value, &text) != nil {
			return fmt.Errorf("mcp: %s.%s must be a string", field, key)
		}
	}
	return nil
}

func validateMCPTaskParams(raw json.RawMessage) error {
	var task map[string]json.RawMessage
	if json.Unmarshal(raw, &task) != nil || task == nil {
		return fmt.Errorf("mcp: task params must be an object")
	}
	if ttl, ok := task["ttl"]; ok && !isJSONNull(ttl) {
		var value uint64
		if json.Unmarshal(ttl, &value) != nil {
			return fmt.Errorf("mcp: task.ttl must be an unsigned integer")
		}
	}
	return nil
}

func isMapValue(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func validateMCPSamplingMessage(raw json.RawMessage) error {
	var message struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &message) != nil || message.Role != "user" && message.Role != "assistant" {
		return fmt.Errorf("mcp: sampling message requires user or assistant role")
	}
	content := bytes.TrimSpace(message.Content)
	if len(content) == 0 {
		return fmt.Errorf("mcp: sampling message requires content")
	}
	blocks := []json.RawMessage{content}
	if content[0] == '[' {
		if json.Unmarshal(content, &blocks) != nil || len(blocks) == 0 {
			return fmt.Errorf("mcp: sampling message content must not be empty")
		}
	} else if content[0] != '{' {
		return fmt.Errorf("mcp: sampling message content must be a content block")
	}
	for _, block := range blocks {
		if err := validateMCPSamplingContentBlock(block); err != nil {
			return err
		}
	}
	return nil
}

func validateMCPSamplingContentBlock(raw json.RawMessage) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return fmt.Errorf("mcp: sampling content block must be an object")
	}
	var kind string
	if json.Unmarshal(object["type"], &kind) != nil {
		return fmt.Errorf("mcp: sampling content block requires type")
	}
	if annotations, ok := object["annotations"]; ok && !isJSONNull(annotations) && kind != "tool_use" && kind != "tool_result" {
		if err := validateMCPContentAnnotations(annotations); err != nil {
			return err
		}
	}
	switch kind {
	case "text":
		var text string
		if json.Unmarshal(object["text"], &text) != nil {
			return fmt.Errorf("mcp: text content block requires text")
		}
	case "image", "audio":
		var data, mimeType string
		if json.Unmarshal(object["data"], &data) != nil || json.Unmarshal(object["mimeType"], &mimeType) != nil {
			return fmt.Errorf("mcp: %s content block requires data and mimeType", kind)
		}
	case "tool_use":
		var id, name string
		var input map[string]json.RawMessage
		if json.Unmarshal(object["id"], &id) != nil || id == "" || json.Unmarshal(object["name"], &name) != nil || name == "" ||
			json.Unmarshal(object["input"], &input) != nil || input == nil {
			return fmt.Errorf("mcp: tool_use content block requires id, name and input object")
		}
	case "tool_result":
		var toolUseID string
		var result struct {
			Content           []json.RawMessage          `json:"content"`
			StructuredContent map[string]json.RawMessage `json:"structuredContent"`
			IsError           *bool                      `json:"isError"`
		}
		if json.Unmarshal(object["toolUseId"], &toolUseID) != nil || toolUseID == "" ||
			json.Unmarshal(raw, &result) != nil || result.Content == nil {
			return fmt.Errorf("mcp: tool_result content block requires toolUseId and content array")
		}
		for _, item := range result.Content {
			if err := validateMCPSamplingContentBlock(item); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("mcp: unsupported sampling content block type")
	}
	return nil
}

func rawJSONPointer(object map[string]json.RawMessage, key string) *json.RawMessage {
	value, ok := object[key]
	if !ok {
		return nil
	}
	return &value
}

func validateMCPResponseID(raw json.RawMessage, allowNull bool) error {
	if len(raw) == 0 {
		return fmt.Errorf("mcp: response id required")
	}
	if isJSONNull(raw) && allowNull {
		return nil
	}
	if err := validateMCPRequestID(raw, true); err != nil {
		return fmt.Errorf("mcp: response id must be string or signed integer")
	}
	return nil
}

const (
	defaultMCPAllowedVersion = "2025-11-25"
	mcpLegacyFallbackVersion = "2025-03-26"
)

var supportedMCPVersions = map[string]struct{}{
	"2025-03-26": {},
	"2025-06-18": {},
	"2025-11-25": {},
}

func validateMCPProtocolVersion(req *http.Request, config *policy.MCPConfig, jsonrpc string, id *json.RawMessage, method string, params *struct {
	Name            string `json:"name"`
	ProtocolVersion string `json:"protocolVersion"`
}) error {
	// OpenShell negotiates a standalone initialize request through its JSON-RPC
	// body. All other requests select exactly one allowed HTTP header revision,
	// with the pinned legacy fallback when the header is absent.
	if jsonrpc == "2.0" && id != nil && method == "initialize" && params != nil && params.ProtocolVersion != "" {
		return nil
	}
	values := req.Header.Values("MCP-Protocol-Version")
	if len(values) > 1 {
		return fmt.Errorf("mcp: protocol version header must have one value")
	}
	for _, connectionValue := range req.Header.Values("Connection") {
		for _, nominated := range strings.Split(connectionValue, ",") {
			if strings.EqualFold(strings.TrimSpace(nominated), "MCP-Protocol-Version") {
				return fmt.Errorf("mcp: protocol version header cannot be connection-nominated")
			}
		}
	}
	version := mcpLegacyFallbackVersion
	if len(values) == 1 {
		version = strings.Trim(values[0], " \t")
		if version == "" {
			return fmt.Errorf("mcp: protocol version header must not be empty")
		}
	}
	if _, ok := supportedMCPVersions[version]; !ok {
		return fmt.Errorf("mcp: unsupported protocol version %q", version)
	}
	allowed := []string{defaultMCPAllowedVersion}
	if config != nil && config.Versions != nil {
		allowed = config.Versions
	}
	for _, candidate := range allowed {
		if version == candidate {
			return nil
		}
	}
	return fmt.Errorf("mcp: protocol version %q is not allowed by endpoint policy", version)
}

// mcpDecidePath builds MatchHTTP path: URL path + NUL + tool (tool may be empty).
func mcpDecidePath(urlPath, tool string) string {
	if urlPath == "" {
		urlPath = "/"
	}
	if tool == "" {
		return urlPath
	}
	return urlPath + "\x00" + tool
}

func isMCPRule(rule *policy.AllowRule) bool {
	return rule != nil && strings.EqualFold(strings.TrimSpace(rule.Protocol), policy.ProtocolMCP)
}
