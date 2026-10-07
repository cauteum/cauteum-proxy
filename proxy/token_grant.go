package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// TokenGrantCredential is the non-secret runtime description needed to obtain
// a short-lived token for one provider credential. Subject tokens stay in the
// gateway vault and are never passed to the proxy.
type TokenGrantCredential struct {
	Provider               string                       `json:"provider"`
	CredentialKey          string                       `json:"credential_key"`
	TokenEndpoint          string                       `json:"token_endpoint"`
	GrantType              string                       `json:"grant_type"`
	Audience               string                       `json:"audience"`
	JWTSVIDAudience        string                       `json:"jwt_svid_audience"`
	ClientAssertionType    string                       `json:"client_assertion_type"`
	RequestedTokenType     string                       `json:"requested_token_type"`
	CacheTTLSeconds        int64                        `json:"cache_ttl_seconds"`
	Scopes                 []string                     `json:"scopes"`
	SubjectTokenType       string                       `json:"subject_token_type"`
	SubjectTokenCredential string                       `json:"subject_token_credential"`
	AudienceOverrides      []TokenGrantAudienceOverride `json:"audience_overrides"`
}

type TokenGrantAudienceOverride struct {
	Host     string   `json:"host"`
	Path     string   `json:"path"`
	Audience string   `json:"audience"`
	Port     int      `json:"port"`
	Scopes   []string `json:"scopes"`
}

type TokenGrantTarget struct {
	Host string
	Port int
	Path string
}

const EnvTokenGrants = "WHALESHELL_TOKEN_GRANTS"

func loadTokenGrantsFromEnviron(environ []string) map[string]TokenGrantCredential {
	for _, entry := range environ {
		key, raw, ok := strings.Cut(entry, "=")
		if !ok || key != EnvTokenGrants || strings.TrimSpace(raw) == "" {
			continue
		}
		var grants map[string]TokenGrantCredential
		if json.Unmarshal([]byte(raw), &grants) != nil {
			return nil
		}
		return grants
	}
	return nil
}

// TokenGrantResolver performs the SVID and OAuth exchange. Implementations
// should cache results only until the returned token's expiry.
type TokenGrantResolver interface {
	ResolveTokenGrant(context.Context, TokenGrantCredential, TokenGrantTarget) (string, error)
}

// SetTokenGrants replaces the proxy's dynamic credential metadata.
func (s *Server) SetTokenGrants(grants map[string]TokenGrantCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenGrants = make(map[string]TokenGrantCredential, len(grants))
	for key, grant := range grants {
		s.tokenGrants[key] = grant
	}
}

// SetTokenGrantResolver installs the workload-identity exchange implementation.
func (s *Server) SetTokenGrantResolver(resolver TokenGrantResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenGrantResolver = resolver
}

func (s *Server) resolveTokenGrantPlaceholders(ctx context.Context, host string, port int, path string, req *http.Request, bound []string, secrets SecretStore) (SecretStore, error) {
	used := PlaceholderKeysInRequest(req)
	return s.resolveTokenGrantKeys(ctx, host, port, path, used, bound, secrets)
}

func (s *Server) resolveTokenGrantKeys(ctx context.Context, host string, port int, path string, used, bound []string, secrets SecretStore) (SecretStore, error) {
	if len(used) == 0 {
		return secrets, nil
	}
	s.mu.RLock()
	grants := s.tokenGrants
	resolver := s.tokenGrantResolver
	s.mu.RUnlock()
	if len(grants) == 0 {
		return secrets, nil
	}
	if resolver == nil {
		return secrets, fmt.Errorf("token grant resolver unavailable")
	}
	boundSet := make(map[string]struct{}, len(bound))
	for _, key := range bound {
		boundSet[key] = struct{}{}
	}
	result := make(SecretStore, len(secrets)+len(used))
	for key, value := range secrets {
		result[key] = value
	}
	target := TokenGrantTarget{Host: host, Port: port, Path: path}
	for _, key := range used {
		grant, ok := grants[key]
		if !ok {
			continue
		}
		if _, ok := boundSet[key]; !ok {
			return nil, fmt.Errorf("%w: key %q not bound to this endpoint", ErrCredentialEndpointMismatch, key)
		}
		value, err := resolver.ResolveTokenGrant(ctx, grant, target)
		if err != nil {
			return nil, fmt.Errorf("provider token grant failed for %s", key)
		}
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("provider token grant returned an empty token")
		}
		result[key] = value
	}
	return result, nil
}
