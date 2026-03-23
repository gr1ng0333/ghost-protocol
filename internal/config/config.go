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

// LogConfig configures logging.
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
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
