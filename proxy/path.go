package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	maxL7PathBytes = 4 << 10
	encodedSlash   = byte(1) // rejected as raw input; reserved as a decoded %2F sentinel
)

// canonicalizeL7Path ports OpenShell's path boundary: policy matching and the
// upstream request use the same canonical escaped path. Path parameters are
// stripped because the pinned OpenShell canonicalizer enables that by default.
func canonicalizeL7Path(raw string, allowEncodedSlash bool) (string, error) {
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x20 || b == 0x7f || b == encodedSlash {
			return "", fmt.Errorf("request path contains a control byte")
		}
		if b >= 0x80 {
			return "", fmt.Errorf("request path contains raw non-ASCII bytes")
		}
	}
	if strings.Contains(raw, "#") {
		return "", fmt.Errorf("request path contains a fragment")
	}
	if raw == "" {
		raw = "/"
	}
	if !strings.HasPrefix(raw, "/") || raw == "*" {
		return "", fmt.Errorf("request path is not origin-form")
	}
	if len(raw) > maxL7PathBytes {
		return "", fmt.Errorf("request path exceeds %d bytes", maxL7PathBytes)
	}

	decoded := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		if raw[i] != '%' {
			decoded = append(decoded, raw[i])
			i++
			continue
		}
		if i+2 >= len(raw) {
			return "", fmt.Errorf("request path contains invalid percent encoding")
		}
		hi, okHi := fromHex(raw[i+1])
		lo, okLo := fromHex(raw[i+2])
		if !okHi || !okLo {
			return "", fmt.Errorf("request path contains invalid percent encoding")
		}
		b := hi<<4 | lo
		switch {
		case b == '/':
			if !allowEncodedSlash {
				return "", fmt.Errorf("request path contains encoded '/' (%%2F), not allowed on this endpoint")
			}
			decoded = append(decoded, encodedSlash)
		case b == 0 || b == 0x7f || b < 0x20:
			return "", fmt.Errorf("request path contains an encoded control byte")
		default:
			decoded = append(decoded, b)
		}
		i += 3
	}
	if len(decoded) == 0 || decoded[0] != '/' {
		return "", fmt.Errorf("request path is not origin-form")
	}

	segments := bytesPathSegments(decoded[1:])
	stack := make([][]byte, 0, len(segments))
	for index, segment := range segments {
		if semicolon := indexByte(segment, ';'); semicolon >= 0 {
			segment = segment[:semicolon]
		}
		last := index == len(segments)-1
		switch string(segment) {
		case "..":
			if len(stack) == 0 {
				return "", fmt.Errorf("request path traversal escapes the root")
			}
			stack = stack[:len(stack)-1]
			if last {
				stack = append(stack, nil)
			}
		case ".":
			if last {
				stack = append(stack, nil)
			}
		default:
			if len(segment) == 0 && !last {
				continue
			}
			stack = append(stack, append([]byte(nil), segment...))
		}
	}
	for _, segment := range stack {
		for _, part := range splitEncodedSlash(segment) {
			if string(part) == "." || string(part) == ".." {
				return "", fmt.Errorf("request path contains a residual dot segment")
			}
		}
	}

	var out strings.Builder
	out.WriteByte('/')
	for i, segment := range stack {
		if i > 0 {
			out.WriteByte('/')
		}
		for _, b := range segment {
			if b == encodedSlash {
				out.WriteString("%2F")
			} else if isPathPChar(b) {
				out.WriteByte(b)
			} else {
				out.WriteByte('%')
				out.WriteByte(upperHex(b >> 4))
				out.WriteByte(upperHex(b & 0x0f))
			}
		}
	}
	return out.String(), nil
}

func requestTargetPath(req *http.Request, fallback string) string {
	if req == nil || req.RequestURI == "" {
		return fallback
	}
	target := req.RequestURI
	if req.URL != nil && req.URL.IsAbs() {
		if schemeEnd := strings.Index(target, "://"); schemeEnd >= 0 {
			authorityStart := schemeEnd + 3
			pathStart := strings.IndexAny(target[authorityStart:], "/?#")
			if pathStart < 0 || target[authorityStart+pathStart] != '/' {
				return "/"
			}
			target = target[authorityStart+pathStart:]
		}
	}
	if query := strings.IndexByte(target, '?'); query >= 0 {
		target = target[:query]
	}
	return target
}

func bytesPathSegments(path []byte) [][]byte {
	parts := make([][]byte, 0, strings.Count(string(path), "/")+1)
	start := 0
	for i, b := range path {
		if b == '/' {
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}
	return append(parts, path[start:])
}

func splitEncodedSlash(segment []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range segment {
		if b == encodedSlash {
			parts = append(parts, segment[start:i])
			start = i + 1
		}
	}
	return append(parts, segment[start:])
}

func indexByte(data []byte, target byte) int {
	for i, b := range data {
		if b == target {
			return i
		}
	}
	return -1
}

func fromHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func upperHex(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + n - 10
}

func isPathPChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		strings.ContainsRune("-._~!$&'()*+,;=:@", rune(b))
}
