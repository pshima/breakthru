package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pshima/breakthru/internal/config"
)

// mockLogger implements the logger.Logger interface for testing
type mockLogger struct {
	mu       sync.Mutex
	messages []logMessage
}

type logMessage struct {
	level string
	msg   string
	args  []any
}

func (m *mockLogger) Info(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, logMessage{level: "info", msg: msg, args: args})
}

func (m *mockLogger) Debug(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, logMessage{level: "debug", msg: msg, args: args})
}

func (m *mockLogger) Warn(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, logMessage{level: "warn", msg: msg, args: args})
}

func (m *mockLogger) Error(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, logMessage{level: "error", msg: msg, args: args})
}

func (m *mockLogger) Close() error {
	return nil
}

func (m *mockLogger) getMessages() []logMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]logMessage, len(m.messages))
	copy(result, m.messages)
	return result
}

func TestNew(t *testing.T) {
	cfg := &config.Config{
		Port:       8080,
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if server == nil {
		t.Fatal("New() returned nil server")
	}

	if server.config != cfg {
		t.Error("Server config not set correctly")
	}

	if server.logger != log {
		t.Error("Server logger not set correctly")
	}

	if server.sessions == nil {
		t.Error("Server sessions map not initialized")
	}

	if server.server == nil {
		t.Error("HTTP server not initialized")
	}
}

func TestServer_HandleHTTP(t *testing.T) {
	cfg := &config.Config{
		Port:       0, // Use any available port
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test HTTP request handling
	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	server.handleHTTP(w, req)

	// Check response
	resp := w.Result()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("handleHTTP() status = %d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "HTTP proxy not yet implemented") {
		t.Errorf("handleHTTP() body = %s, want error message", string(body))
	}

	// Check logs
	foundInfoLog := false
	for _, msg := range log.getMessages() {
		if msg.level == "info" && strings.Contains(msg.msg, "HTTP request") {
			foundInfoLog = true
			break
		}
	}
	if !foundInfoLog {
		t.Error("Expected info log for HTTP request not found")
	}
}

func TestServer_HandleConnect(t *testing.T) {
	cfg := &config.Config{
		Port:       0,
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test CONNECT request handling
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	w := httptest.NewRecorder()

	server.handleConnect(w, req)

	// Check response
	resp := w.Result()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("handleConnect() status = %d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "CONNECT not yet implemented") {
		t.Errorf("handleConnect() body = %s, want error message", string(body))
	}

	// Check logs
	foundInfoLog := false
	for _, msg := range log.getMessages() {
		if msg.level == "info" && strings.Contains(msg.msg, "CONNECT request") {
			foundInfoLog = true
			break
		}
	}
	if !foundInfoLog {
		t.Error("Expected info log for CONNECT request not found")
	}
}

func TestServer_CreateHandler(t *testing.T) {
	cfg := &config.Config{
		Port:       0,
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := server.createHandler()
	if handler == nil {
		t.Fatal("createHandler() returned nil")
	}

	// Test the handler routes correctly
	tests := []struct {
		name   string
		method string
		url    string
		want   string
	}{
		{
			name:   "CONNECT method",
			method: http.MethodConnect,
			url:    "example.com:443",
			want:   "CONNECT not yet implemented",
		},
		{
			name:   "GET method",
			method: http.MethodGet,
			url:    "http://example.com/test",
			want:   "HTTP proxy not yet implemented",
		},
		{
			name:   "POST method",
			method: http.MethodPost,
			url:    "http://example.com/api",
			want:   "HTTP proxy not yet implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.url, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tt.want) {
				t.Errorf("Handler response = %s, want containing %s", string(body), tt.want)
			}
		})
	}
}

func TestServer_LogHeaders(t *testing.T) {
	cfg := &config.Config{
		Port:       0,
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer token123"},
		"X-Custom":      []string{"value1", "value2"},
	}

	server.logHeaders("Test", headers)

	// Check that headers were logged
	headerLogsFound := 0
	for _, msg := range log.getMessages() {
		if msg.level == "debug" && strings.Contains(msg.msg, "Test header") {
			headerLogsFound++
		}
	}

	// Should have logged 4 headers (1 + 1 + 2)
	if headerLogsFound != 4 {
		t.Errorf("logHeaders() logged %d headers, want 4", headerLogsFound)
	}
}

func TestServer_GetActiveSessions(t *testing.T) {
	cfg := &config.Config{
		Port:       0,
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Add some test sessions
	session1 := &Session{
		ID:        "session1",
		StartTime: time.Now(),
		ClientIP:  "192.168.1.1",
	}
	session2 := &Session{
		ID:        "session2",
		StartTime: time.Now(),
		ClientIP:  "192.168.1.2",
	}

	server.sessions[session1.ID] = session1
	server.sessions[session2.ID] = session2

	// Get active sessions
	sessions := server.GetActiveSessions()

	if len(sessions) != 2 {
		t.Errorf("GetActiveSessions() returned %d sessions, want 2", len(sessions))
	}

	// Verify sessions are correctly returned
	if sessions["session1"].ClientIP != "192.168.1.1" {
		t.Error("Session1 not returned correctly")
	}
	if sessions["session2"].ClientIP != "192.168.1.2" {
		t.Error("Session2 not returned correctly")
	}

	// Modify returned map shouldn't affect original
	delete(sessions, "session1")
	if len(server.sessions) != 2 {
		t.Error("Modifying returned sessions affected original map")
	}
}

func TestServer_Start(t *testing.T) {
	cfg := &config.Config{
		Port:       0, // Use any available port
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Wait for server to be ready
	var addr string
	for i := 0; i < 20; i++ {
		addr = server.GetListenerAddr()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	
	if addr == "" {
		t.Fatal("Server listener not created")
	}
	
	// Make a test request
	resp, err := http.Get(fmt.Sprintf("http://%s/test", addr))
	if err != nil {
		t.Fatalf("Failed to make test request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("Test request status = %d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}

	// Shutdown server
	cancel()

	// Wait for server to stop
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Server.Start() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Server shutdown timeout")
	}

	// Check shutdown log
	foundShutdownLog := false
	for _, msg := range log.getMessages() {
		if msg.level == "info" && strings.Contains(msg.msg, "Shutting down") {
			foundShutdownLog = true
			break
		}
	}
	if !foundShutdownLog {
		t.Error("Expected shutdown log not found")
	}
}

func TestServer_StartHTTPS(t *testing.T) {
	// Create temporary cert and key files
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHpKKmk/qFMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAYTAlVT
MB4XDTE2MTAwMTAwMDAwMFoXDTI2MDkzMDAwMDAwMFowDTELMAkGA1UEBhMCVVMw
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOY7pjHsBA7gDGkFDpRFAZsilSJI
xlOl9t2lmFhGKKKEHZkANteRXIFg6xT6lGm5FSuvXWTsB2lhUw2CFl7N/MlmvLqN
l8lPZ4omQIFwDU/NfEA6YnlJVpGEZSwnjVbVQ2xYGahQxn4gZgLkzR0SL9bhjyDm
8B2V2T3R7JuEhbkFAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAunxjeRbF/KvcLCfb
mGZqf5h4Qkqh1p7XYL6TfmqYM+w7u2rLiG4MNGIqDyR7F5aLZzDKZBMwJX1br+2E
YYjP4fGTFRJLfHPxFfTXRuY8cYDgLCQhD0D7vvjp0c0gG8pTxONTBp0AngP4z5sc
j4xU0gKVA8u158W/M8EhOGNbFwU=
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDmO6Yx7AQO4AxpBQ6URQGbIpUiSMZTpfbdpZhYRiiihB2ZADLX
kVyBYOsU+pRpuRUrr11k7AdpYVMNghZezfzJZry6jZfJT2eKJkCBcA1PzXxAOmJ5
SVaRhGUsJ41W1UNsWBmoUMZ+IGIC5M0dEi/W4Y8g5vAdldk90eyLhIW5BQIDAQAB
AoGAVOYPA/7aIPLVTVEWFT4lhLl5JTQqno9Y3N2zU1t3RpHGLpL4ZWjLgBfavz9o
r7Qm9g5+fUMc3/zU4lqaGLXYDDlruKHG3PBx9vu2kNPv4XYFKoQT7w1InIMKkBOS
CEUM5qe0VBjQ8RuhLXc2a3wvFCJKCqJwsVEaJ8RWPzC9TgECQQD0+c9bwco8re0o
YJQqVkj1kPTGY4RXdMPAFCmHLtjVnPacrNOXgPLBWNvKWEakHjwPcOrrsIm7lbz9
C9ztHeKlAkEA8DURke1EvH9R3JYfqiYp1usRWd8cJ1pCxVn3DW0LxpkRbpqN2CJu
JcgF2KYnLa7G8+PW0FEbjRZWQpYsxGJrYQJBAOGeDUTo9wa/gJlZvPJOCwWLzEan
YWkRs6xwJDaWYqKQs9JtlVMCsoduGIFYdCJIQEQYO3HKkqmJmK+5TnA5aKECQQDm
hq2HfCsy8gEar8Fnk8gPRYa/V+khj2RQBAdVnhVEFj1CvfJWV0VRYPMhZseCF9Ik
WMYeYaBfKiPTW4Dtu1UhAkBMYj0MUCQta3Qy3XSK5GrlLBX9UW8j5mjQu5P2KcrH
0KVbQIVqUxBNPxe1hTPBue1OqLgLOLv1lUaXKTeQTbTN
-----END RSA PRIVATE KEY-----`

	// Write cert and key to temp files
	tmpDir := t.TempDir()
	certFile := tmpDir + "/cert.pem"
	keyFile := tmpDir + "/key.pem"
	
	if err := os.WriteFile(certFile, []byte(certPEM), 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte(keyPEM), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := &config.Config{
		Port:       0,
		HTTPSMode:  true,
		CertFile:   certFile,
		KeyFile:    keyFile,
		BufferSize: 32768,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Check that HTTPS server started
	foundHTTPSLog := false
	for _, msg := range log.getMessages() {
		if msg.level == "info" && strings.Contains(msg.msg, "Starting HTTPS proxy server") {
			foundHTTPSLog = true
			break
		}
	}
	if !foundHTTPSLog {
		t.Error("Expected HTTPS start log not found")
	}

	// Shutdown server
	cancel()

	// Wait for server to stop
	select {
	case <-errChan:
		// Expected
	case <-time.After(2 * time.Second):
		t.Error("Server shutdown timeout")
	}
}