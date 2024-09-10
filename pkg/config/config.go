package config

import (
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v2"
)

// Config represents a config file
type Config struct {
	Interfaces []string `yaml:"interfaces"`
	Backends   []string `yaml:"backends"`
	backends   []netip.Addr
}

// GetConfig gets the config
func GetConfig(fp string) (*Config, error) {
	fc, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("Unable to read file: %w", err)
	}

	cfg := &Config{
		Interfaces: make([]string, 0),
		Backends:   make([]string, 0),
		backends:   make([]netip.Addr, 0),
	}

	err = yaml.Unmarshal(fc, cfg)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal YAML file: %w", err)
	}

	for _, b := range cfg.Backends {
		a, err := netip.ParseAddr(b)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse IP '%s': %w", b, err)
		}

		cfg.backends = append(cfg.backends, a)
	}

	return cfg, nil
}

// GetBackends gets the backends
func (c *Config) GetBackends() []netip.Addr {
	return c.backends
}
