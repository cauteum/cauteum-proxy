package config

import (
	"os"
	"strings"
)

// Config is process-level proxy configuration from the environment.
type Config struct {
	Listen     string
	PolicyPath string
	LogLevel   string
}

// Load reads CAUTEUM_* defaults (CLI flags override at call site).
func Load() Config {
	return Config{
		Listen:     strings.TrimSpace(os.Getenv("CAUTEUM_PROXY_LISTEN")),
		PolicyPath: strings.TrimSpace(os.Getenv("CAUTEUM_PROXY_POLICY")),
		LogLevel:   strings.TrimSpace(os.Getenv("CAUTEUM_LOG_LEVEL")),
	}
}
