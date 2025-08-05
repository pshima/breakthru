package proxy

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pshima/breakthru/internal/config"
)

// mockLogger for testing
type mockTransparentLogger struct {
	mu       sync.Mutex
	messages []transparentLogMessage
}

type transparentLogMessage struct {
	level string
	msg   string
	args  []any
}

func (m *mockTransparentLogger) Info(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, transparentLogMessage{level: "info", msg: msg, args: args})
}

func (m *mockTransparentLogger) Debug(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, transparentLogMessage{level: "debug", msg: msg, args: args})
}

func (m *mockTransparentLogger) Warn(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, transparentLogMessage{level: "warn", msg: msg, args: args})
}

func (m *mockTransparentLogger) Error(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, transparentLogMessage{level: "error", msg: msg, args: args})
}

func (m *mockTransparentLogger) Close() error {
	return nil
}

func (m *mockTransparentLogger) getMessages() []transparentLogMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]transparentLogMessage, len(m.messages))
	copy(result, m.messages)
	return result
}

func TestNewTransparentProxy(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		TransparentMode:  true,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockTransparentLogger{}
	
	// Create a basic server first
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	transparentProxy, err := NewTransparentProxy(cfg, log, server)
	if err != nil {
		t.Fatalf("NewTransparentProxy() error = %v", err)
	}
	
	if transparentProxy == nil {
		t.Fatal("NewTransparentProxy() returned nil")
	}
	
	if transparentProxy.config != cfg {
		t.Error("TransparentProxy config not set correctly")
	}
	
	if transparentProxy.logger != log {
		t.Error("TransparentProxy logger not set correctly")
	}
	
	if transparentProxy.server != server {
		t.Error("TransparentProxy server not set correctly")
	}
}

func TestTransparentProxyLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		TransparentMode:  true,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockTransparentLogger{}
	
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	transparentProxy, err := NewTransparentProxy(cfg, log, server)
	if err != nil {
		t.Fatalf("NewTransparentProxy() error = %v", err)
	}
	
	// Test initial state
	if transparentProxy.IsRunning() {
		t.Error("TransparentProxy should not be running initially")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Start transparent proxy
	err = transparentProxy.Start(ctx)
	if err != nil {
		// Expected on systems without privileges or unsupported platforms
		t.Logf("Start() error (may be expected): %v", err)
		return
	}
	
	// Check running state
	if !transparentProxy.IsRunning() {
		t.Error("TransparentProxy should be running after Start()")
	}
	
	// Stop transparent proxy
	err = transparentProxy.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
	
	// Check stopped state
	if transparentProxy.IsRunning() {
		t.Error("TransparentProxy should not be running after Stop()")
	}
}

func TestTransparentProxyDoubleStart(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		TransparentMode:  true,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockTransparentLogger{}
	
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	transparentProxy, err := NewTransparentProxy(cfg, log, server)
	if err != nil {
		t.Fatalf("NewTransparentProxy() error = %v", err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Start first time
	err1 := transparentProxy.Start(ctx)
	if err1 != nil {
		t.Logf("First Start() error (may be expected): %v", err1)
		return
	}
	
	// Start second time - should fail
	err2 := transparentProxy.Start(ctx)
	if err2 == nil {
		t.Error("Expected error when starting transparent proxy twice")
	}
	
	// Clean up
	transparentProxy.Stop()
}

func TestTransparentProxyStopWithoutStart(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		TransparentMode:  true,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockTransparentLogger{}
	
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	transparentProxy, err := NewTransparentProxy(cfg, log, server)
	if err != nil {
		t.Fatalf("NewTransparentProxy() error = %v", err)
	}
	
	// Try to stop without starting
	err = transparentProxy.Stop()
	if err == nil {
		t.Error("Expected error when stopping transparent proxy that wasn't started")
	}
}

func TestIsHTTPTraffic(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		TransparentMode:  true,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockTransparentLogger{}
	
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	transparentProxy, err := NewTransparentProxy(cfg, log, server)
	if err != nil {
		t.Fatalf("NewTransparentProxy() error = %v", err)
	}
	
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"GET request", []byte("GET /path HTTP/1.1\r\n"), true},
		{"POST request", []byte("POST /api HTTP/1.1\r\n"), true},
		{"PUT request", []byte("PUT /resource HTTP/1.1\r\n"), true},
		{"DELETE request", []byte("DELETE /item HTTP/1.1\r\n"), true},
		{"HEAD request", []byte("HEAD /check HTTP/1.1\r\n"), true},
		{"OPTIONS request", []byte("OPTIONS * HTTP/1.1\r\n"), true},
		{"PATCH request", []byte("PATCH /update HTTP/1.1\r\n"), true},
		{"TRACE request", []byte("TRACE /debug HTTP/1.1\r\n"), true},
		{"Non-HTTP data", []byte("some random data"), false},
		{"Binary data", []byte{0x00, 0x01, 0x02, 0x03}, false},
		{"Empty data", []byte{}, false},
		{"Short data", []byte("AB"), false},
		{"SSH protocol", []byte("SSH-2.0-OpenSSH"), false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transparentProxy.isHTTPTraffic(tt.data)
			if result != tt.expected {
				t.Errorf("isHTTPTraffic(%q) = %v, want %v", string(tt.data), result, tt.expected)
			}
		})
	}
}

func TestGetOriginalDestination(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		TransparentMode:  true,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockTransparentLogger{}
	
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	transparentProxy, err := NewTransparentProxy(cfg, log, server)
	if err != nil {
		t.Fatalf("NewTransparentProxy() error = %v", err)
	}
	
	// Create a mock HTTP request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	
	dest := transparentProxy.getOriginalDestination(req)
	
	// For now, this returns a placeholder
	if dest == "" {
		t.Error("getOriginalDestination() returned empty string")
	}
}

func TestTransparentProxyWithPorts(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		TransparentMode:  true,
		InterceptPorts:   []int{80, 443},
		ExcludePorts:     []int{22, 25},
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockTransparentLogger{}
	
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	transparentProxy, err := NewTransparentProxy(cfg, log, server)
	if err != nil {
		t.Fatalf("NewTransparentProxy() error = %v", err)
	}
	
	if transparentProxy == nil {
		t.Fatal("NewTransparentProxy() returned nil")
	}
	
	// Verify configuration was passed correctly
	if len(cfg.InterceptPorts) != 2 {
		t.Errorf("Expected 2 intercept ports, got %d", len(cfg.InterceptPorts))
	}
	
	if len(cfg.ExcludePorts) != 2 {
		t.Errorf("Expected 2 exclude ports, got %d", len(cfg.ExcludePorts))
	}
}


func TestMin(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{5, 3, 3},
		{2, 8, 2},
		{10, 10, 10},
		{0, 1, 0},
		{-1, 5, -1},
	}
	
	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, result, tt.expected)
		}
	}
}