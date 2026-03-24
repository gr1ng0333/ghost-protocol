package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ClientConfig is the client configuration.
type ClientConfig struct {
	Server  ServerEndpoint `yaml:"server"`
	Auth    AuthConfig     `yaml:"auth"`
	Proxy   ProxyConfig    `yaml:"proxy"`
	Shaping ShapingConfig  `yaml:"shaping"`
	Log     LogConfig      `yaml:"log"`
}

// ServerConfig is the server configuration.
type ServerConfig struct {
	Listen   string         `yaml:"listen"`
	Domain   string         `yaml:"domain"`
	TLS      TLSConfig      `yaml:"tls"`
	Auth     AuthConfig     `yaml:"auth"`
	Backend  BackendConfig  `yaml:"backend"`
	Shaping  ShapingConfig  `yaml:"shaping"`
	Fallback FallbackConfig `yaml:"fallback"`
	Sessions SessionConfig  `yaml:"sessions"`
	Log      LogConfig      `yaml:"log"`
}

// SessionConfig configures server-side session management.
type SessionConfig struct {
	MaxSessions    int `yaml:"max_sessions"`
	IdleTimeoutSec int `yaml:"idle_timeout_sec"`
}

// ServerEndpoint defines how to connect to the Ghost server.
type ServerEndpoint struct {
	Addr string `yaml:"addr"`
	SNI  string `yaml:"sni"`
}

// AuthConfig holds authentication parameters.
type AuthConfig struct {
	ServerPublicKey  string `yaml:"server_public_key"`
	ServerPrivateKey string `yaml:"server_private_key"`
	ClientPublicKey  string `yaml:"client_public_key"`
	ClientPrivateKey string `yaml:"client_private_key"`
}

// ProxyConfig configures client-side traffic capture.
type ProxyConfig struct {
	Mode    string `yaml:"mode"`
	Socks5  string `yaml:"socks5"`
	TunName string `yaml:"tun_name"`
	DNS     string `yaml:"dns"`
}

// ShapingConfig configures traffic shaping.
type ShapingConfig struct {
	DefaultMode string `yaml:"default_mode"`
	ProfilePath string `yaml:"profile_path"`
	ProfileDir  string `yaml:"profile_dir"`
	AutoMode    bool   `yaml:"auto_mode"`
}

// BackendConfig configures server-side proxying.
type BackendConfig struct {
	AllowedPorts []uint16 `yaml:"allowed_ports"`
}

// FallbackConfig configures the fallback web server.
type FallbackConfig struct {
	Addr     string `yaml:"addr"`
	WebRoot  string `yaml:"web_root"`
	UseCaddy bool   `yaml:"use_caddy"`
}

// TLSConfig configures server TLS certificate management.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	AutoCert bool   `yaml:"auto_cert"`
	Email    string `yaml:"email"`
	CacheDir string `yaml:"cache_dir"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
	Format string `yaml:"format"` // "json" or "text" (default: "json" server, "text" client)
	File   string `yaml:"file"`   // path, or "stdout"/"stderr"
}

// Defaults fills zero-value fields with sensible defaults.
func (c *ServerConfig) Defaults() {
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.Sessions.MaxSessions == 0 {
		c.Sessions.MaxSessions = 10
	}
	if c.Sessions.IdleTimeoutSec == 0 {
		c.Sessions.IdleTimeoutSec = 300
	}
	if c.Shaping.DefaultMode == "" {
		c.Shaping.DefaultMode = "balanced"
	}
	if c.Shaping.ProfilePath == "" {
		c.Shaping.ProfilePath = "profiles/chrome_browsing.json"
	}
	if c.TLS.CacheDir == "" {
		c.TLS.CacheDir = "/var/lib/ghost/certs"
	}
	if c.Fallback.Addr == "" {
		c.Fallback.Addr = "127.0.0.1:8080"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	if c.Log.File == "" {
		c.Log.File = "stdout"
	}
}

// Defaults fills zero-value fields with sensible defaults.
func (c *ClientConfig) Defaults() {
	if c.Shaping.DefaultMode == "" {
		c.Shaping.DefaultMode = "balanced"
	}
	if c.Shaping.ProfilePath == "" {
		c.Shaping.ProfilePath = "profiles/chrome_browsing.json"
	}
	if c.Proxy.Mode == "" {
		c.Proxy.Mode = "socks5"
	}
	if c.Proxy.Socks5 == "" {
		c.Proxy.Socks5 = "127.0.0.1:1080"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.Log.File == "" {
		c.Log.File = "stdout"
	}
}

// Load reads a YAML config file and unmarshals into the given target.
// target must be a pointer to ClientConfig or ServerConfig.
func Load(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config.Load(%s): %w", path, err)
	}

	if err := yaml.Unmarshal(data, target); err != nil {
		return fmt.Errorf("config.Load(%s): %w", path, err)
	}

	return nil
}
