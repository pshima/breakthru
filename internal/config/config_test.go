package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	if cfg.Port != 8080 {
		t.Errorf("DefaultConfig() Port = %d, want 8080", cfg.Port)
	}
	if cfg.LogFile != "breakthru.log" {
		t.Errorf("DefaultConfig() LogFile = %s, want breakthru.log", cfg.LogFile)
	}
	if cfg.HTTPSMode {
		t.Error("DefaultConfig() HTTPSMode = true, want false")
	}
	if cfg.BufferSize != 32*1024 {
		t.Errorf("DefaultConfig() BufferSize = %d, want %d", cfg.BufferSize, 32*1024)
	}
	if cfg.Verbose {
		t.Error("DefaultConfig() Verbose = true, want false")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid HTTP config",
			config: &Config{
				Port:            8080,
				HTTPSMode:       false,
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: false,
		},
		{
			name: "valid HTTPS config with user certs",
			config: &Config{
				Port:            8443,
				HTTPSMode:       true,
				CertFile:        "cert.pem",
				KeyFile:         "key.pem",
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: false,
		},
		{
			name: "valid HTTPS config with CA certs",
			config: &Config{
				Port:            8443,
				HTTPSMode:       true,
				CACert:          "ca-cert.pem",
				CAKey:           "ca-key.pem",
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: false,
		},
		{
			name: "invalid port too low",
			config: &Config{
				Port:            0,
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: true,
			errMsg:  "invalid port number",
		},
		{
			name: "invalid port too high",
			config: &Config{
				Port:            70000,
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: true,
			errMsg:  "invalid port number",
		},
		{
			name: "HTTPS mode without certs",
			config: &Config{
				Port:            8443,
				HTTPSMode:       true,
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: true,
			errMsg:  "HTTPS mode requires either cert_file or ca_cert",
		},
		{
			name: "cert file without key file",
			config: &Config{
				Port:            8443,
				HTTPSMode:       true,
				CertFile:        "cert.pem",
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: true,
			errMsg:  "cert_file requires key_file",
		},
		{
			name: "CA cert without CA key",
			config: &Config{
				Port:            8443,
				HTTPSMode:       true,
				CACert:          "ca-cert.pem",
				BufferSize:      4096,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: true,
			errMsg:  "ca_cert requires ca_key",
		},
		{
			name: "buffer size too small",
			config: &Config{
				Port:            8080,
				BufferSize:      512,
				CertValidityDays: 365,
				CertKeySize:     2048,
				CertStoreDir:    "./certs",
			},
			wantErr: true,
			errMsg:  "buffer_size must be at least 1024 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("Config.Validate() error = %v, want error containing %s", err, tt.errMsg)
			}
		})
	}
}

func TestLoad_FromFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-config.json")
	
	testConfig := &Config{
		Port:            9090,
		CertFile:        "/path/to/cert.pem",
		KeyFile:         "/path/to/key.pem",
		LogFile:         "custom.log",
		Verbose:         true,
		HTTPSMode:       true,
		BufferSize:      65536,
		TargetHosts:     []string{"api.example.com", "game.example.com"},
		CertValidityDays: 365,
		CertKeySize:     2048,
		CertStoreDir:    "./certs",
	}
	
	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	
	// Test loading from file
	cfg, err := Load(configFile, CLIOptions{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	
	if cfg.Port != 9090 {
		t.Errorf("Load() Port = %d, want 9090", cfg.Port)
	}
	if cfg.LogFile != "custom.log" {
		t.Errorf("Load() LogFile = %s, want custom.log", cfg.LogFile)
	}
	if !cfg.Verbose {
		t.Error("Load() Verbose = false, want true")
	}
	if !reflect.DeepEqual(cfg.TargetHosts, testConfig.TargetHosts) {
		t.Errorf("Load() TargetHosts = %v, want %v", cfg.TargetHosts, testConfig.TargetHosts)
	}
}

func TestLoad_CLIOverride(t *testing.T) {
	// Create a config file with default values
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-config.json")
	
	fileConfig := &Config{
		Port:            8080,
		LogFile:         "file.log",
		Verbose:         false,
		HTTPSMode:       false,
		BufferSize:      32768,
		CertValidityDays: 365,
		CertKeySize:     2048,
		CertStoreDir:    "./certs",
	}
	
	data, err := json.MarshalIndent(fileConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	
	// Test CLI options override
	cliOpts := CLIOptions{
		Port:       9999,
		CertFile:   "cli-cert.pem",
		KeyFile:    "cli-key.pem",
		LogFile:    "cli.log",
		Verbose:    true,
		VerboseSet: true,
	}
	
	cfg, err := Load(configFile, cliOpts)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	
	// Verify CLI options took precedence
	if cfg.Port != 9999 {
		t.Errorf("Load() Port = %d, want 9999 (CLI override)", cfg.Port)
	}
	if cfg.CertFile != "cli-cert.pem" {
		t.Errorf("Load() CertFile = %s, want cli-cert.pem", cfg.CertFile)
	}
	if cfg.KeyFile != "cli-key.pem" {
		t.Errorf("Load() KeyFile = %s, want cli-key.pem", cfg.KeyFile)
	}
	if cfg.LogFile != "cli.log" {
		t.Errorf("Load() LogFile = %s, want cli.log", cfg.LogFile)
	}
	if !cfg.Verbose {
		t.Error("Load() Verbose = false, want true (CLI override)")
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
	// Test loading with no config file (CLI options only)
	cliOpts := CLIOptions{
		Port:    8888,
		LogFile: "test.log",
	}
	
	cfg, err := Load("", cliOpts)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	
	// Should use defaults with CLI overrides
	if cfg.Port != 8888 {
		t.Errorf("Load() Port = %d, want 8888", cfg.Port)
	}
	if cfg.LogFile != "test.log" {
		t.Errorf("Load() LogFile = %s, want test.log", cfg.LogFile)
	}
	if cfg.HTTPSMode {
		t.Error("Load() HTTPSMode = true, want false (default)")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.json")
	
	// Write invalid JSON
	if err := os.WriteFile(configFile, []byte("{ invalid json }"), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
	
	_, err := Load(configFile, CLIOptions{})
	if err == nil {
		t.Error("Load() with invalid JSON should return error")
	}
	if !contains(err.Error(), "failed to parse config file") {
		t.Errorf("Load() error = %v, want error about parsing", err)
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	_, err := Load("/non/existent/file.json", CLIOptions{})
	if err == nil {
		t.Error("Load() with non-existent file should return error")
	}
	if !contains(err.Error(), "failed to read config file") {
		t.Errorf("Load() error = %v, want error about reading file", err)
	}
}

func TestConfig_Save(t *testing.T) {
	tmpDir := t.TempDir()
	saveFile := filepath.Join(tmpDir, "save-test.json")
	
	cfg := &Config{
		Port:            8443,
		CertFile:        "test-cert.pem",
		KeyFile:         "test-key.pem",
		LogFile:         "test.log",
		Verbose:         true,
		HTTPSMode:       true,
		CACert:          "ca-cert.pem",
		CAKey:           "ca-key.pem",
		TargetHosts:     []string{"host1.com", "host2.com"},
		BufferSize:      65536,
		CertValidityDays: 365,
		CertKeySize:     2048,
		CertStoreDir:    "./certs",
	}
	
	// Save config
	if err := cfg.Save(saveFile); err != nil {
		t.Fatalf("Config.Save() error = %v", err)
	}
	
	// Load it back
	loaded, err := Load(saveFile, CLIOptions{})
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}
	
	// Verify all fields match
	if !reflect.DeepEqual(cfg, loaded) {
		t.Errorf("Saved and loaded configs don't match.\nOriginal: %+v\nLoaded: %+v", cfg, loaded)
	}
}

func TestConfig_Save_InvalidPath(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Save("/invalid\x00path/config.json")
	if err == nil {
		t.Error("Config.Save() with invalid path should return error")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}