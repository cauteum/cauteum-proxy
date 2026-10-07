package proxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/whaleshell/whaleshell-core/env"
)

// SecretStore maps env key to secret value for placeholder rewrite.
type SecretStore map[string]string

// FilterSecrets returns a copy of secrets limited to allowed keys.
// Empty allowed means an empty store (no unbound rewrite) — OpenShell-style endpoint binding.
func FilterSecrets(secrets SecretStore, allowed []string) SecretStore {
	if secrets == nil || len(allowed) == 0 {
		return SecretStore{}
	}
	out := make(SecretStore, len(allowed))
	for _, k := range allowed {
		if v, ok := secrets[k]; ok {
			out[k] = v
		}
	}
	return out
}

// ErrCredentialEndpointMismatch is returned when a placeholder is used on an
// endpoint that does not bind that credential key (OpenShell credential_endpoint_mismatch).
var ErrCredentialEndpointMismatch = fmt.Errorf("credential_endpoint_mismatch")

// PlaceholderKeysInRequest lists env keys referenced by whaleshell:/openshell:resolve:env markers
// in path, query, and headers (including Basic).
func PlaceholderKeysInRequest(req *http.Request) []string {
	if req == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		for _, k := range placeholderKeysInString(s) {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	if req.URL != nil {
		add(req.URL.EscapedPath())
		if dec, err := url.PathUnescape(req.URL.EscapedPath()); err == nil {
			add(dec)
		}
		add(req.URL.RawQuery)
	}
	for _, vv := range req.Header {
		for _, v := range vv {
			add(v)
			trimmed := strings.TrimSpace(v)
			if strings.HasPrefix(strings.ToLower(trimmed), "basic ") {
				enc := strings.TrimSpace(trimmed[6:])
				if raw, err := base64.StdEncoding.DecodeString(enc); err == nil {
					add(string(raw))
				}
			}
		}
	}
	return out
}

func placeholderKeysInString(s string) []string {
	if !env.ContainsPlaceholder(s) {
		return nil
	}
	var out []string
	rest := s
	for {
		i, prefixLen := env.IndexPlaceholder(rest)
		if i < 0 {
			break
		}
		rest = rest[i:]
		if prefixLen > len(rest) {
			break
		}
		j := prefixLen
		for j < len(rest) {
			c := rest[j]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
				j++
				continue
			}
			break
		}
		if j > prefixLen {
			out = append(out, rest[prefixLen:j])
		}
		rest = rest[j:]
	}
	return out
}

// SecretsForEndpoint returns secrets allowed for rewrite on the matched endpoint.
// Any placeholder key not listed in boundKeys fails closed with ErrCredentialEndpointMismatch.
func SecretsForEndpoint(secrets SecretStore, boundKeys, usedKeys []string) (SecretStore, error) {
	bound := map[string]struct{}{}
	for _, k := range boundKeys {
		k = strings.TrimSpace(k)
		if k != "" {
			bound[k] = struct{}{}
		}
	}
	for _, k := range usedKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := bound[k]; !ok {
			return nil, fmt.Errorf("%w: key %q not bound to this endpoint", ErrCredentialEndpointMismatch, k)
		}
	}
	return FilterSecrets(secrets, boundKeys), nil
}

// controlPlaneKeys are gateway credentials of the sidecar itself; a sandbox
// placeholder must never resolve them into outbound traffic.
var controlPlaneKeys = map[string]struct{}{
	"WHALESHELL_SANDBOX_TOKEN": {},
	"WHALESHELL_GATEWAY_TOKEN": {},
}

// LoadSecretsFromEnviron builds a store from KEY=VAL entries (skips passthrough
// and control-plane keys).
func LoadSecretsFromEnviron(environ []string) SecretStore {
	out := make(SecretStore)
	for _, entry := range environ {
		k, v, ok := strings.Cut(entry, "=")
		if !ok || k == "" || v == "" {
			continue
		}
		if env.IsPassthrough(k) {
			continue
		}
		if _, ok := controlPlaneKeys[k]; ok {
			continue
		}
		out[k] = v
	}
	return out
}

// ContainsPlaceholder reports whether s has a reserved credential marker.
func ContainsPlaceholder(s string) bool {
	return env.ContainsPlaceholder(s)
}

// RewriteHTTPRequest resolves placeholders in path, query, and headers (incl. Basic).
// Fail-closed: unresolved markers return an error (do not send upstream).
func RewriteHTTPRequest(req *http.Request, secrets SecretStore) error {
	return RewriteHTTPRequestWithOptions(req, secrets, false)
}

// RewriteHTTPRequestWithOptions optionally rewrites textual REST body markers.
// Body rewriting is explicitly opt-in per endpoint, matching OpenShell policy.
func RewriteHTTPRequestWithOptions(req *http.Request, secrets SecretStore, rewriteBody bool) error {
	if req == nil {
		return nil
	}
	if req.URL != nil {
		escapedPath := req.URL.EscapedPath()
		marker := string(encodedSlash)
		protectedPath := strings.ReplaceAll(escapedPath, "%2F", marker)
		protectedPath = strings.ReplaceAll(protectedPath, "%2f", marker)
		path, err := rewritePath(protectedPath, secrets)
		if err != nil {
			return err
		}
		rawQuery, err := rewriteQuery(req.URL.RawQuery, secrets)
		if err != nil {
			return err
		}
		if path != protectedPath {
			if strings.Contains(path, marker) {
				req.URL.Path = strings.ReplaceAll(path, marker, "/")
				req.URL.RawPath = strings.ReplaceAll(path, marker, "%2F")
			} else {
				req.URL.Path = path
				req.URL.RawPath = ""
			}
		}
		req.URL.RawQuery = rawQuery
	}
	for k, vv := range req.Header {
		for i, v := range vv {
			nv, err := rewriteHeaderValue(v, secrets)
			if err != nil {
				return fmt.Errorf("header %s: %w", k, err)
			}
			if nv != v {
				vv[i] = nv
			}
		}
		req.Header[k] = vv
	}
	if rewriteBody {
		if err := rewriteRequestBody(req, secrets); err != nil {
			return err
		}
	}
	return nil
}

const maxCredentialRewriteBodyBytes = 256 << 10

func rewriteRequestBody(req *http.Request, secrets SecretStore) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxCredentialRewriteBodyBytes+1))
	closeErr := req.Body.Close()
	if err != nil {
		return fmt.Errorf("request body credential rewrite: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("request body credential rewrite: %w", closeErr)
	}
	if len(body) > maxCredentialRewriteBodyBytes {
		return fmt.Errorf("request body credential rewrite exceeds %d bytes", maxCredentialRewriteBodyBytes)
	}
	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	mediaType = strings.ToLower(mediaType)
	textual := strings.HasPrefix(mediaType, "text/") || mediaType == "application/json" || mediaType == "application/x-www-form-urlencoded"
	if !textual {
		if ContainsPlaceholder(string(body)) {
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))
			return fmt.Errorf("request body credential rewrite requires a supported textual content type")
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		return nil
	}
	if !utf8.Valid(body) {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		if ContainsPlaceholder(string(body)) {
			return fmt.Errorf("request body credential rewrite requires valid UTF-8")
		}
		return nil
	}
	var rewritten string
	if mediaType == "application/x-www-form-urlencoded" {
		rewritten, err = rewriteFormBody(string(body), secrets)
	} else {
		rewritten, err = rewriteText(string(body), secrets)
	}
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		return fmt.Errorf("request body credential rewrite: %w", err)
	}
	newBody := []byte(rewritten)
	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
	req.Header.Del("Transfer-Encoding")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
	return nil
}

func rewriteFormBody(body string, secrets SecretStore) (string, error) {
	fields := strings.Split(body, "&")
	for i, field := range fields {
		key, value, hasValue := strings.Cut(field, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			return "", fmt.Errorf("invalid form field name: %w", err)
		}
		if ContainsPlaceholder(decodedKey) {
			return "", fmt.Errorf("credential placeholders in form field names are unsupported")
		}
		if !hasValue {
			continue
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return "", fmt.Errorf("invalid form field value: %w", err)
		}
		if !ContainsPlaceholder(decodedValue) {
			continue
		}
		decodedValue, err = rewriteText(decodedValue, secrets)
		if err != nil {
			return "", err
		}
		fields[i] = key + "=" + url.QueryEscape(decodedValue)
	}
	return strings.Join(fields, "&"), nil
}

// RewriteText resolves all placeholders in an arbitrary string (WS text frames).
func RewriteText(text string, secrets SecretStore) (string, error) {
	return rewriteText(text, secrets)
}

func rewriteHeaderValue(value string, secrets SecretStore) (string, error) {
	trimmed := strings.TrimSpace(value)
	// Basic auth: placeholder lives inside base64 — check before ContainsPlaceholder short-circuit.
	if strings.HasPrefix(strings.ToLower(trimmed), "basic ") {
		enc := strings.TrimSpace(trimmed[6:])
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			if ContainsPlaceholder(trimmed) {
				return "", fmt.Errorf("basic auth decode: %w", err)
			}
			return value, nil
		}
		decoded := string(raw)
		if ContainsPlaceholder(decoded) {
			rewritten, err := rewriteText(decoded, secrets)
			if err != nil {
				return "", err
			}
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(rewritten)), nil
		}
		return value, nil
	}
	if !ContainsPlaceholder(trimmed) {
		return value, nil
	}
	// Exact placeholder
	if secret, ok := resolveExact(trimmed, secrets); ok {
		return secret, nil
	}
	// Prefixed: Bearer whaleshell:resolve:env:KEY
	if i := strings.IndexFunc(trimmed, func(r rune) bool { return r == ' ' || r == '\t' }); i > 0 {
		prefix := trimmed[:i]
		cand := strings.TrimSpace(trimmed[i:])
		if secret, ok := resolveExact(cand, secrets); ok {
			return prefix + " " + secret, nil
		}
		if ContainsPlaceholder(cand) {
			return "", fmt.Errorf("unresolved placeholder in header")
		}
	}
	if ContainsPlaceholder(trimmed) {
		return rewriteText(trimmed, secrets)
	}
	return value, nil
}

func resolveExact(token string, secrets SecretStore) (string, bool) {
	key, ok := env.ParsePlaceholder(token)
	if !ok {
		return "", false
	}
	secret, found := secrets[key]
	return secret, found && secret != ""
}

func rewriteText(text string, secrets SecretStore) (string, error) {
	if !ContainsPlaceholder(text) {
		return text, nil
	}
	var b strings.Builder
	b.Grow(len(text))
	rest := text
	for {
		i, prefixLen := env.IndexPlaceholder(rest)
		if i < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:i])
		rest = rest[i:]
		if prefixLen > len(rest) {
			return "", fmt.Errorf("unresolved placeholder")
		}
		j := prefixLen
		for j < len(rest) {
			c := rest[j]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
				j++
				continue
			}
			break
		}
		if j == prefixLen {
			return "", fmt.Errorf("unresolved placeholder")
		}
		key := rest[prefixLen:j]
		secret, ok := secrets[key]
		if !ok || secret == "" {
			return "", fmt.Errorf("unresolved placeholder %s%s", env.PlaceholderPrefix, key)
		}
		b.WriteString(secret)
		rest = rest[j:]
	}
	return b.String(), nil
}

func rewritePath(escapedPath string, secrets SecretStore) (string, error) {
	if escapedPath == "" || !ContainsPlaceholder(escapedPath) {
		// Also check decoded form
		decoded, err := url.PathUnescape(escapedPath)
		if err != nil || !ContainsPlaceholder(decoded) {
			return escapedPath, nil
		}
		rewritten, err := rewriteText(decoded, secrets)
		if err != nil {
			return "", err
		}
		return rewritten, nil
	}
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil {
		decoded = escapedPath
	}
	return rewriteText(decoded, secrets)
}

func rewriteQuery(raw string, secrets SecretStore) (string, error) {
	if raw == "" || !ContainsPlaceholder(raw) {
		return raw, nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", fmt.Errorf("query: %w", err)
	}
	changed := false
	for k, vv := range q {
		for i, v := range vv {
			nv, err := rewriteText(v, secrets)
			if err != nil {
				return "", fmt.Errorf("query %s: %w", k, err)
			}
			if nv != v {
				vv[i] = nv
				changed = true
			}
		}
		q[k] = vv
	}
	if !changed {
		return raw, nil
	}
	return q.Encode(), nil
}
