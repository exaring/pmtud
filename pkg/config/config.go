package config

import (
	"io/ioutil"
	"net"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Config represents a config file
type Config struct {
	Interfaces   []string `yaml:"interfaces"`
	Backends     []string `yaml:"backends"`
	backendsIPv4 []net.IP
	backendsIPv6 []net.IP
}

// GetConfig gets the config
func GetConfig(fp string) (*Config, error) {
	fc, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to read file")
	}

	cfg := &Config{
		Interfaces:   make([]string, 0),
		Backends:     make([]string, 0),
		backendsIPv4: make([]net.IP, 0),
		backendsIPv6: make([]net.IP, 0),
	}

	err = yaml.Unmarshal(fc, cfg)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to unmarshal YAML file")
	}

	for _, b := range cfg.Backends {
		a := net.ParseIP(b)
		if a == nil {
			return nil, errors.Wrapf(err, "Unable to parse IP: %s", b)
		}

		if a.To4() != nil {
			cfg.backendsIPv4 = append(cfg.backendsIPv4, a)
		} else {
			cfg.backendsIPv6 = append(cfg.backendsIPv6, a)
		}
	}

	return cfg, nil
}

// GetBackendsIPv4 gets the IPv4 backends
func (c *Config) GetBackendsIPv4() []net.IP {
	return c.backendsIPv4
}

// GetBackendsIPv6 gets the IPv6 backends
func (c *Config) GetBackendsIPv6() []net.IP {
	return c.backendsIPv6
}
