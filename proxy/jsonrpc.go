package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cautem/cauteum-core/policy"
)

const defaultJSONRPCMaxBodyBytes = 64 << 10

// parseJSONRPCRequest validates JSON-RPC 2.0 request envelopes and returns
// every method so policy can authorize every member of a batch independently.
func parseJSONRPCRequest(req *http.Request, config *policy.JSONRPCConfig) ([]string, error) {
	if req == nil {
		return nil, fmt.Errorf("json-rpc: missing request")
	}
	noBody := req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0
	if noBody {
		if strings.EqualFold(req.Method, http.MethodGet) && requestAcceptsJSONRPCStream(req) {
			return []string{http.MethodGet}, nil // JSON-RPC receive stream.
		}
		return nil, fmt.Errorf("json-rpc: request body required (GET requires Accept: text/event-stream)")
	}
	maxBytes := uint32(defaultJSONRPCMaxBodyBytes)
	if config != nil && config.MaxBodyBytes != nil && *config.MaxBodyBytes > 0 {
		maxBytes = *config.MaxBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, int64(maxBytes)+1))
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("json-rpc: read request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.Header.Del("Transfer-Encoding")
	if uint64(len(body)) > uint64(maxBytes) {
		return nil, fmt.Errorf("json-rpc: request body exceeds %d bytes", maxBytes)
	}
	var root json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("json-rpc: invalid JSON")
	}
	root = bytes.TrimSpace(root)
	var items []json.RawMessage
	if len(root) > 0 && root[0] == '[' {
		if err := json.Unmarshal(root, &items); err != nil || len(items) == 0 {
			return nil, fmt.Errorf("json-rpc: batch must be a non-empty array")
		}
	} else {
		items = []json.RawMessage{root}
	}
	methods := make([]string, 0, len(items))
	for _, item := range items {
		var fields map[string]json.RawMessage
		if len(item) == 0 || item[0] != '{' || json.Unmarshal(item, &fields) != nil {
			return nil, fmt.Errorf("json-rpc: each message must be an object")
		}
		var version string
		if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" {
			return nil, fmt.Errorf("json-rpc: jsonrpc must be 2.0")
		}
		hasResult := fields["result"] != nil
		hasError := fields["error"] != nil
		if hasResult || hasError {
			if fields["method"] != nil {
				return nil, fmt.Errorf("json-rpc: message contains both method and response payload")
			}
			return nil, fmt.Errorf("json-rpc: response messages are not permitted from client to server")
		}
		var method string
		if rawMethod, ok := fields["method"]; !ok || json.Unmarshal(rawMethod, &method) != nil {
			return nil, fmt.Errorf("json-rpc: method must be a string")
		}
		methods = append(methods, method)
	}
	return methods, nil
}

func requestAcceptsJSONRPCStream(req *http.Request) bool {
	for _, header := range req.Header.Values("Accept") {
		for _, mediaType := range strings.Split(header, ",") {
			mediaType, _, _ = strings.Cut(strings.TrimSpace(mediaType), ";")
			if strings.EqualFold(strings.TrimSpace(mediaType), "text/event-stream") {
				return true
			}
		}
	}
	return false
}
