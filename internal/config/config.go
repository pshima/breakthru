package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all application configuration
type Config struct {
	Port            int      `json:"port"`
	CertFile        string   `json:"cert_file"`
	KeyFile         string   `json:"key_file"`
	LogFile         string   `json:"log_file"`
	Verbose         bool     `json:"verbose"`
	HTTPSMode       bool     `json:"https_mode"`
	CACert          string   `json:"ca_cert"`
	CAKey           string   `json:"ca_key"`
	TargetHosts     []string `json:"target_hosts"`
	BufferSize      int      `json:"buffer_size"`
	TransparentMode bool     `json:"transparent_mode"`
	InterceptPorts  []int    `json:"intercept_ports"`
	ExcludePorts    []int    `json:"exclude_ports"`
	
	// Certificate management settings
	CertStoreDir       string `json:"cert_store_dir"`       // Directory to store generated certificates
	AutoGenerateCA     bool   `json:"auto_generate_ca"`     // Auto-generate CA if none provided
	CertValidityDays   int    `json:"cert_validity_days"`   // Days certificates are valid for
	CertKeySize        int    `json:"cert_key_size"`        // RSA key size for generated certificates
	CertCleanupEnabled bool   `json:"cert_cleanup_enabled"` // Enable automatic cleanup of expired certificates
	
	// HTTPS interception settings
	HTTPSInterception      bool     `json:"https_interception"`        // Enable HTTPS interception and decryption
	HTTPSTransparent       bool     `json:"https_transparent"`         // Enable transparent HTTPS interception
	HTTPSSkipVerify        bool     `json:"https_skip_verify"`         // Skip server certificate verification
	HTTPSBypassDomains     []string `json:"https_bypass_domains"`      // Domains to bypass HTTPS interception
	HTTPSOnlyDomains       []string `json:"https_only_domains"`        // Only intercept these domains (if specified)
	HTTPSLogBodies         bool     `json:"https_log_bodies"`          // Log request/response bodies for HTTPS
	HTTPSMaxBodySize       int      `json:"https_max_body_size"`       // Maximum body size to log (bytes)
}

// CLIOptions represents command-line options
type CLIOptions struct {
	Port            int
	CertFile        string
	KeyFile         string
	LogFile         string
	Verbose         bool
	Enable          bool
	Disable         bool
	TransparentMode bool
	
	// Flags to track which options were explicitly set
	VerboseSet         bool
	TransparentModeSet bool
	
	// Certificate management CLI options
	GenerateCA    bool
	CertInfo      string
	InstallCA     string
	UninstallCA   string
	ListCerts     bool
	CleanupCerts  bool
	GenCert       []string
	ValidateCert  string
	ValidateHost  string
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Port:       8080,
		LogFile:    "breakthru.log",
		HTTPSMode:  false, // Default to HTTP mode since no certs are provided
		BufferSize: 32 * 1024, // 32KB default buffer
		Verbose:    false,
		
		// Certificate management defaults
		CertStoreDir:       "./certs",
		AutoGenerateCA:     true,
		CertValidityDays:   365,
		CertKeySize:        2048,
		CertCleanupEnabled: true,
		
		// HTTPS interception defaults
		HTTPSInterception:  true,
		HTTPSTransparent:   true,
		HTTPSSkipVerify:    false,
		HTTPSLogBodies:     true,
		HTTPSMaxBodySize:   1024 * 1024, // 1MB
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
	if cliOpts.VerboseSet {
		cfg.Verbose = cliOpts.Verbose
	}
	if cliOpts.TransparentModeSet {
		cfg.TransparentMode = cliOpts.TransparentMode
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

	// Validate certificate settings
	if c.CertValidityDays < 1 {
		return fmt.Errorf("cert_validity_days must be at least 1")
	}

	if c.CertKeySize < 1024 {
		return fmt.Errorf("cert_key_size must be at least 1024")
	}

	if c.CertStoreDir == "" {
		return fmt.Errorf("cert_store_dir cannot be empty")
	}

	// Validate HTTPS interception settings
	if c.HTTPSMaxBodySize < 0 {
		return fmt.Errorf("https_max_body_size cannot be negative")
	}

	if c.HTTPSInterception && !c.AutoGenerateCA && c.CACert == "" {
		return fmt.Errorf("HTTPS interception requires CA certificate or auto-generation enabled")
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