package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all application configuration
type Config struct {
	Port        int                `json:"port"`
	CertFile    string             `json:"cert_file"`
	KeyFile     string             `json:"key_file"`
	LogFile     string             `json:"log_file"`
	Verbose     bool               `json:"verbose"`
	HTTPSMode   bool               `json:"https_mode"`
	CACert      string             `json:"ca_cert"`
	CAKey       string             `json:"ca_key"`
	TargetHosts []string           `json:"target_hosts"`
	BufferSize  int                `json:"buffer_size"`
}

// CLIOptions represents command-line options
type CLIOptions struct {
	Port     int
	CertFile string
	KeyFile  string
	LogFile  string
	Verbose  bool
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Port:       8080,
		LogFile:    "breakthru.log",
		HTTPSMode:  false, // Default to HTTP mode since no certs are provided
		BufferSize: 32 * 1024, // 32KB default buffer
		Verbose:    false,
	}
}

// Load loads configuration from file and merges with CLI options
func Load(configFile string, cliOpts CLIOptions) (*Config, error) {
	cfg := DefaultConfig()

	// Load from file if provided
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override with CLI options
	if cliOpts.Port != 0 {
		cfg.Port = cliOpts.Port
	}
	if cliOpts.CertFile != "" {
		cfg.CertFile = cliOpts.CertFile
	}
	if cliOpts.KeyFile != "" {
		cfg.KeyFile = cliOpts.KeyFile
	}
	if cliOpts.LogFile != "" {
		cfg.LogFile = cliOpts.LogFile
	}
	if cliOpts.Verbose {
		cfg.Verbose = cliOpts.Verbose
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", c.Port)
	}

	if c.HTTPSMode {
		// Check if we have either user certs or CA certs for generation
		if c.CertFile == "" && c.CACert == "" {
			return fmt.Errorf("HTTPS mode requires either cert_file or ca_cert")
		}
		if c.CertFile != "" && c.KeyFile == "" {
			return fmt.Errorf("cert_file requires key_file")
		}
		if c.CACert != "" && c.CAKey == "" {
			return fmt.Errorf("ca_cert requires ca_key")
		}
	}

	if c.BufferSize < 1024 {
		return fmt.Errorf("buffer_size must be at least 1024 bytes")
	}

	return nil
}

// Save writes the configuration to a file
func (c *Config) Save(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}