package middleware

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

// FromEnviron builds an optional pipeline from WHALESHELL_MIDDLEWARE_* env vars.
//
//	WHALESHELL_MIDDLEWARE_JWT_AUD      — removed; setting it denies requests
//	WHALESHELL_MIDDLEWARE_JWT_REQUIRED — removed; setting it denies requests
//	WHALESHELL_MIDDLEWARE_REMOTE_URL   — POST Decision JSON stage (fail-closed)
func FromEnviron(environ []string) *Pipeline {
	if environ == nil {
		environ = os.Environ()
	}
	env := map[string]string{}
	for _, e := range environ {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			env[k] = v
		}
	}
	var stages []Stage
	aud := strings.TrimSpace(env["WHALESHELL_MIDDLEWARE_JWT_AUD"])
	jwtRequired := strings.TrimSpace(env["WHALESHELL_MIDDLEWARE_JWT_REQUIRED"])
	if aud != "" || jwtRequired != "" && !strings.EqualFold(jwtRequired, "false") && jwtRequired != "0" {
		stages = append(stages, &rejectedConfigStage{
			Label:  "removed_jwt_env",
			Reason: "JWT middleware environment configuration was removed; refusing request",
		})
	}
	if u := strings.TrimSpace(env["WHALESHELL_MIDDLEWARE_REMOTE_URL"]); u != "" {
		stages = append(stages, &remoteStage{URL: u, FailClosed: true, Label: "remote_env"})
	}
	if raw := strings.TrimSpace(env["WHALESHELL_SUPERVISOR_MIDDLEWARES"]); raw != "" {
		var configured []grpcMiddlewareConfig
		if err := json.Unmarshal([]byte(raw), &configured); err != nil {
			stages = append(stages, &rejectedConfigStage{Label: "supervisor_middleware_config", Reason: "invalid supervisor middleware configuration"})
		} else {
			sort.SliceStable(configured, func(i, j int) bool {
				if configured[i].Order != configured[j].Order {
					return configured[i].Order < configured[j].Order
				}
				return configured[i].Name < configured[j].Name
			})
			for _, item := range configured {
				roots := (*x509.CertPool)(nil)
				if item.TLSCAPEM != "" {
					pool := x509.NewCertPool()
					pemBytes, err := base64.StdEncoding.DecodeString(item.TLSCAPEM)
					if err != nil || !pool.AppendCertsFromPEM(pemBytes) {
						stages = append(stages, &rejectedConfigStage{Label: item.Name, Reason: "invalid supervisor middleware CA bundle"})
						continue
					}
					roots = pool
				}
				config, err := structValue(item.Config)
				if err != nil {
					stages = append(stages, &rejectedConfigStage{Label: item.Name, Reason: "invalid supervisor middleware policy config"})
					continue
				}
				timeout, err := time.ParseDuration(item.Timeout)
				if err != nil || timeout <= 0 {
					timeout = 500 * time.Millisecond
				}
				stage, err := NewGRPCStage(GRPCStageConfig{Name: item.Name, Endpoint: item.Endpoint, Timeout: timeout, FailClosed: item.FailClosed, Config: config, TLSRoots: roots, MaxPayloadBytes: item.MaxPayloadBytes, Order: item.Order, Include: item.Include, Exclude: item.Exclude})
				if err != nil {
					stages = append(stages, &rejectedConfigStage{Label: item.Name, Reason: "invalid supervisor middleware endpoint"})
					continue
				}
				stages = append(stages, stage)
			}
		}
	}
	if len(stages) == 0 {
		return nil
	}
	return &Pipeline{Stages: stages}
}

type grpcMiddlewareConfig struct {
	Name            string         `json:"name"`
	Endpoint        string         `json:"endpoint"`
	Timeout         string         `json:"timeout"`
	FailClosed      bool           `json:"fail_closed"`
	MaxPayloadBytes uint64         `json:"max_payload_bytes,omitempty"`
	Order           int32          `json:"order"`
	Include         []string       `json:"include,omitempty"`
	Exclude         []string       `json:"exclude,omitempty"`
	Config          map[string]any `json:"config,omitempty"`
	TLSCAPEM        string         `json:"tls_ca_cert_pem,omitempty"`
}

func structValue(fields map[string]any) (*structpb.Struct, error) {
	if fields == nil {
		return nil, nil
	}
	return structpb.NewStruct(fields)
}
