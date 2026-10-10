package proxy

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// parsePolicyQuery follows OpenShell rest.rs: preserve repeated keys and empty
// values, decode plus/percent, reject malformed escapes and non-UTF-8, and treat
// semicolons as literal characters rather than additional separators.
func parsePolicyQuery(raw string) (map[string][]string, error) {
	values := make(map[string][]string)
	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(key)
		if err != nil {
			return nil, fmt.Errorf("invalid percent encoding")
		}
		value, err = url.QueryUnescape(value)
		if err != nil {
			return nil, fmt.Errorf("invalid percent encoding")
		}
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return nil, fmt.Errorf("component is not valid UTF-8")
		}
		values[key] = append(values[key], value)
	}
	return values, nil
}
