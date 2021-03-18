package config

import (
	"io/ioutil"
	"net"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Config represents a config file
type Config struct {
	Interfaces []string `yaml:"interfaces"`
	Backends   []string `yaml:"backends"`
	backends   []net.IP
}

// GetConfig gets the config
func GetConfig(fp string) (*Config, error) {
	fc, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to read file")
	}

	cfg := &Config{
		Interfaces: make([]string, 0),
		Backends:   make([]string, 0),
		backends:   make([]net.IP, 0),
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

		cfg.backends = append(cfg.backends, a)
	}

	return cfg, nil
}

// GetBackends gets the backends
func (c *Config) GetBackends() []net.IP {
	return c.backends
}
