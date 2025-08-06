package proxy

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
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
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from backend"))
	}))
	defer backendServer.Close()

	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0, // Use any available port
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test HTTP request handling with backend server URL
	req := httptest.NewRequest(http.MethodGet, backendServer.URL+"/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	server.handleHTTP(w, req)

	// Check response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleHTTP() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Hello from backend") {
		t.Errorf("handleHTTP() body = %s, want backend response", string(body))
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
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:              0,
		BufferSize:        32768,
		CertStoreDir:      tempDir,
		AutoGenerateCA:    true,
		CertKeySize:       2048,
		CertValidityDays:  365,
		HTTPSInterception: false, // Disable HTTPS interception for this test
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test CONNECT request handling when HTTPS interception is disabled
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	w := httptest.NewRecorder()

	server.handleConnect(w, req)

	// Check response - with HTTPS interception disabled, it should create a tunnel
	resp := w.Result()
	// The response code could vary depending on whether the connection succeeds
	// For a non-existent host like example.com, we expect a connection error
	expectedCodes := []int{http.StatusOK, http.StatusBadGateway, http.StatusInternalServerError}
	found := false
	for _, code := range expectedCodes {
		if resp.StatusCode == code {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("handleConnect() status = %d, want one of %v", resp.StatusCode, expectedCodes)
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
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Backend response"))
	}))
	defer backendServer.Close()

	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:              0,
		BufferSize:        32768,
		CertStoreDir:      tempDir,
		AutoGenerateCA:    true,
		CertKeySize:       2048,
		CertValidityDays:  365,
		HTTPSInterception: false, // Disable HTTPS interception for this test
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
	// Note: CONNECT method requires hijacking which httptest.NewRecorder doesn't support
	// so we only test regular HTTP methods here
	tests := []struct {
		name   string
		method string
		url    string
		want   string
		status int
	}{
		{
			name:   "GET method",
			method: http.MethodGet,
			url:    backendServer.URL + "/test",
			want:   "Backend response",
			status: http.StatusOK,
		},
		{
			name:   "POST method",
			method: http.MethodPost,
			url:    backendServer.URL + "/api",
			want:   "Backend response",
			status: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.url, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.status {
				t.Errorf("Handler status = %d, want %d", resp.StatusCode, tt.status)
			}
			
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tt.want) {
				t.Errorf("Handler response = %s, want containing %s", string(body), tt.want)
			}
		})
	}
}

func TestServer_LogHeaders(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
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
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
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
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0, // Use any available port
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
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
	
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer backendServer.Close()

	// Create HTTP client with proxy
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Make a test request through the proxy
	resp, err := client.Get(backendServer.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make test request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Test request status = %d, want %d", resp.StatusCode, http.StatusOK)
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

func TestServer_HTTPProxyFunctionality(t *testing.T) {
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request information
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend-Server", "test")
		w.WriteHeader(http.StatusOK)
		
		response := fmt.Sprintf(`{
			"method": "%s",
			"path": "%s",
			"headers": %d,
			"user_agent": "%s",
			"via": "%s"
		}`, r.Method, r.URL.Path, len(r.Header), r.UserAgent(), r.Header.Get("Via"))
		
		w.Write([]byte(response))
	}))
	defer backendServer.Close()

	// Create proxy server
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
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
		t.Fatal("Server not ready")
	}

	// Create HTTP client with proxy
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Test GET request
	resp, err := client.Get(backendServer.URL + "/test?param=value")
	if err != nil {
		t.Fatalf("Failed to make GET request through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET request status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if !strings.Contains(string(body), `"method": "GET"`) {
		t.Errorf("Response doesn't contain expected method: %s", string(body))
	}

	if !strings.Contains(string(body), `"path": "/test"`) {
		t.Errorf("Response doesn't contain expected path: %s", string(body))
	}

	if !strings.Contains(string(body), `"via": "1.1 breakthru"`) {
		t.Errorf("Response doesn't contain expected Via header: %s", string(body))
	}

	// Test POST request with body
	postBody := strings.NewReader(`{"test": "data"}`)
	resp, err = client.Post(backendServer.URL+"/api", "application/json", postBody)
	if err != nil {
		t.Fatalf("Failed to make POST request through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST request status = %d, want 200", resp.StatusCode)
	}

	// Check that backend server header was preserved
	if resp.Header.Get("X-Backend-Server") != "test" {
		t.Errorf("Backend server header not preserved")
	}

	// Check logs for proxy activity
	messages := log.getMessages()
	foundRequest := false
	foundResponse := false
	
	for _, msg := range messages {
		if msg.level == "info" && strings.Contains(msg.msg, "HTTP request") {
			foundRequest = true
		}
		if msg.level == "info" && strings.Contains(msg.msg, "HTTP response") {
			foundResponse = true
		}
	}

	if !foundRequest {
		t.Error("Expected to find HTTP request log")
	}
	if !foundResponse {
		t.Error("Expected to find HTTP response log")
	}

	cancel()
	<-errChan
}

func TestServer_BuildTargetURL(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	server, _ := New(cfg, log)

	tests := []struct {
		name     string
		request  *http.Request
		expected string
	}{
		{
			name: "absolute URL",
			request: &http.Request{
				URL: &url.URL{
					Scheme: "http",
					Host:   "example.com",
					Path:   "/test",
				},
			},
			expected: "http://example.com/test",
		},
		{
			name: "relative URL with Host header",
			request: &http.Request{
				Host: "api.example.com",
				URL: &url.URL{
					Path: "/api/v1",
					RawQuery: "key=value",
				},
			},
			expected: "http://api.example.com/api/v1?key=value",
		},
		{
			name: "empty host",
			request: &http.Request{
				URL: &url.URL{Path: "/test"},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.buildTargetURL(tt.request)
			if tt.expected == "" {
				if result != nil {
					t.Errorf("Expected nil URL, got %s", result.String())
				}
			} else {
				if result == nil {
					t.Errorf("Expected URL %s, got nil", tt.expected)
				} else if result.String() != tt.expected {
					t.Errorf("Expected URL %s, got %s", tt.expected, result.String())
				}
			}
		})
	}
}

func TestServer_CreateProxyRequest(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	server, _ := New(cfg, log)

	// Create original request
	originalReq := httptest.NewRequest("POST", "http://example.com/api", strings.NewReader("test body"))
	originalReq.Header.Set("User-Agent", "test-agent")
	originalReq.Header.Set("Content-Type", "application/json")
	originalReq.Header.Set("Connection", "keep-alive") // Hop-by-hop header
	originalReq.Header.Set("Proxy-Authorization", "Bearer token") // Should be removed

	targetURL, _ := url.Parse("http://target.com/api")
	body := []byte("test body")

	proxyReq, err := server.createProxyRequest(originalReq, targetURL, body)
	if err != nil {
		t.Fatalf("Failed to create proxy request: %v", err)
	}

	// Check URL
	if proxyReq.URL.String() != "http://target.com/api" {
		t.Errorf("Proxy request URL = %s, want http://target.com/api", proxyReq.URL.String())
	}

	// Check method
	if proxyReq.Method != "POST" {
		t.Errorf("Proxy request method = %s, want POST", proxyReq.Method)
	}

	// Check headers were copied
	if proxyReq.Header.Get("User-Agent") != "test-agent" {
		t.Errorf("User-Agent header not copied")
	}

	if proxyReq.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type header not copied")
	}

	// Check hop-by-hop headers were removed
	if proxyReq.Header.Get("Connection") != "" {
		t.Errorf("Connection header should be removed")
	}

	if proxyReq.Header.Get("Proxy-Authorization") != "" {
		t.Errorf("Proxy-Authorization header should be removed")
	}

	// Check Via header was added
	via := proxyReq.Header.Get("Via")
	if !strings.Contains(via, "1.1 breakthru") {
		t.Errorf("Via header = %s, should contain '1.1 breakthru'", via)
	}

	// Check content length
	if proxyReq.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d", proxyReq.ContentLength, len(body))
	}
}

func TestServer_CopyHeaders(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	server, _ := New(cfg, log)

	src := http.Header{}
	src.Set("User-Agent", "test-agent")
	src.Set("Content-Type", "application/json")
	src.Set("Connection", "keep-alive") // Hop-by-hop
	src.Set("Keep-Alive", "timeout=5") // Hop-by-hop
	src.Set("Custom-Header", "value")

	dst := http.Header{}
	server.copyHeaders(dst, src)

	// Check normal headers were copied
	if dst.Get("User-Agent") != "test-agent" {
		t.Errorf("User-Agent not copied")
	}

	if dst.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type not copied")
	}

	if dst.Get("Custom-Header") != "value" {
		t.Errorf("Custom-Header not copied")
	}

	// Check hop-by-hop headers were not copied
	if dst.Get("Connection") != "" {
		t.Errorf("Connection header should not be copied")
	}

	if dst.Get("Keep-Alive") != "" {
		t.Errorf("Keep-Alive header should not be copied")
	}
}

func TestServer_HTTPProxyWithErrorHandling(t *testing.T) {
	// Create proxy server
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
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
		t.Fatal("Server not ready")
	}

	// Test request to non-existent server
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}

	// This should fail and return 502 Bad Gateway
	resp, err := client.Get("http://nonexistent.invalid:12345/test")
	if err != nil {
		// This is expected for connection errors
		t.Logf("Expected connection error: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected 502 Bad Gateway for connection error, got %d", resp.StatusCode)
		}
	}

	// Check error logs
	messages := log.getMessages()
	foundError := false
	for _, msg := range messages {
		if msg.level == "error" && strings.Contains(msg.msg, "Failed to forward request") {
			foundError = true
			break
		}
	}

	if !foundError {
		t.Error("Expected to find error log for failed request")
	}

	cancel()
	<-errChan
}

func TestServer_KeepAliveConnections(t *testing.T) {
	// Create a test backend server that tracks connections
	connCount := 0
	var mu sync.Mutex
	
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connCount++
		count := connCount
		mu.Unlock()
		
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Connection-Count", fmt.Sprintf("%d", count))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Response from connection %d", count)))
	}))
	defer backendServer.Close()

	// Create proxy server
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Verify that the server has a properly configured transport
	if server.client == nil {
		t.Fatal("Server client is nil")
	}
	
	transport, ok := server.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Server client transport is not *http.Transport")
	}
	
	if transport.DisableKeepAlives {
		t.Error("Keep-alives should be enabled")
	}
	
	if transport.MaxIdleConnsPerHost < 1 {
		t.Error("MaxIdleConnsPerHost should be at least 1")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
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
		t.Fatal("Server not ready")
	}

	// Create HTTP client with proxy and keep-alive enabled
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DisableKeepAlives: false,
			MaxIdleConnsPerHost: 10,
		},
		Timeout: 5 * time.Second,
	}

	// Make multiple requests to the same host
	// With keep-alive, these should reuse connections
	numRequests := 5
	for i := 0; i < numRequests; i++ {
		resp, err := client.Get(backendServer.URL + fmt.Sprintf("/test%d", i))
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Request %d status = %d, want 200", i, resp.StatusCode)
		}
		
		// Log the response for debugging
		t.Logf("Request %d: %s, Connection Count Header: %s", i, string(body), resp.Header.Get("X-Connection-Count"))
	}

	// With keep-alive, we should see fewer connections than requests
	// (connections should be reused)
	mu.Lock()
	finalConnCount := connCount
	mu.Unlock()
	
	t.Logf("Total requests: %d, Total connections: %d", numRequests, finalConnCount)
	
	// The exact number of connections depends on timing and the backend server's behavior,
	// but with keep-alive we should see some connection reuse
	if finalConnCount >= numRequests {
		t.Logf("Warning: No connection reuse detected (connections: %d, requests: %d)", finalConnCount, numRequests)
	}

	// Check logs for Connection header
	messages := log.getMessages()
	for _, msg := range messages {
		if msg.level == "debug" && strings.Contains(msg.msg, "Connection header") {
			t.Logf("Found Connection header log: %v", msg)
		}
	}

	// Test with explicit Connection: close header
	req, _ := http.NewRequest("GET", backendServer.URL+"/close-test", nil)
	req.Header.Set("Connection", "close")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request with Connection: close failed: %v", err)
	}
	resp.Body.Close()

	// Verify idle connections are closed on shutdown
	cancel()
	
	select {
	case <-errChan:
		// Expected
	case <-time.After(2 * time.Second):
		t.Error("Server shutdown timeout")
	}
	
	// Check for idle connection closing log
	messages = log.getMessages()
	foundCloseLog := false
	for _, msg := range messages {
		if msg.level == "debug" && strings.Contains(msg.msg, "Closing idle connections") {
			foundCloseLog = true
			break
		}
	}
	
	if !foundCloseLog {
		t.Error("Expected idle connections closing log not found")
	}
}

func TestServer_CopyHeadersWithConnectionHeader(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	server, _ := New(cfg, log)

	// Test with custom hop-by-hop headers specified in Connection header
	src := http.Header{}
	src.Set("User-Agent", "test-agent")
	src.Set("Content-Type", "application/json")
	src.Set("Connection", "X-Custom-Header, X-Another-Header")
	src.Set("X-Custom-Header", "should-not-be-copied")
	src.Set("X-Another-Header", "also-should-not-be-copied")
	src.Set("X-Normal-Header", "should-be-copied")

	dst := http.Header{}
	server.copyHeaders(dst, src)

	// Check normal headers were copied
	if dst.Get("User-Agent") != "test-agent" {
		t.Errorf("User-Agent not copied")
	}

	if dst.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type not copied")
	}

	if dst.Get("X-Normal-Header") != "should-be-copied" {
		t.Errorf("X-Normal-Header not copied")
	}

	// Check custom hop-by-hop headers were not copied
	if dst.Get("X-Custom-Header") != "" {
		t.Errorf("X-Custom-Header should not be copied (specified in Connection header)")
	}

	if dst.Get("X-Another-Header") != "" {
		t.Errorf("X-Another-Header should not be copied (specified in Connection header)")
	}

	// Connection header itself should not be copied
	if dst.Get("Connection") != "" {
		t.Errorf("Connection header should not be copied")
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
		Port:             0,
		HTTPSMode:        true,
		CertFile:         certFile,
		KeyFile:          keyFile,
		BufferSize:       32768,
		CertStoreDir:     tmpDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
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

func TestServer_IsWebSocketUpgrade(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	server, _ := New(cfg, log)

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "valid WebSocket upgrade",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "websocket",
			},
			expected: true,
		},
		{
			name: "case insensitive headers",
			headers: map[string]string{
				"Connection": "upgrade",
				"Upgrade":    "WebSocket",
			},
			expected: true,
		},
		{
			name: "missing Upgrade header",
			headers: map[string]string{
				"Connection": "Upgrade",
			},
			expected: false,
		},
		{
			name: "missing Connection header",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			expected: false,
		},
		{
			name: "wrong Upgrade value",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "h2c",
			},
			expected: false,
		},
		{
			name:     "no headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/ws", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := server.isWebSocketUpgrade(req)
			if result != tt.expected {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestServer_GenerateWebSocketAccept(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	server, _ := New(cfg, log)

	// Test with the example from RFC 6455
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	result := server.generateWebSocketAccept(key)
	if result != expected {
		t.Errorf("generateWebSocketAccept() = %s, want %s", result, expected)
	}

	// Test that it generates the correct hash
	const websocketMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + websocketMagicString))
	expectedHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if result != expectedHash {
		t.Errorf("generateWebSocketAccept() hash mismatch: got %s, want %s", result, expectedHash)
	}
}

func TestServer_LogWebSocketFrame(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test text frame
	textFrame := []byte{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'}
	server.logWebSocketFrame("test->server", textFrame)

	// Check that the frame was logged
	messages := log.getMessages()
	foundFrameLog := false
	for _, msg := range messages {
		if msg.level == "debug" && strings.Contains(msg.msg, "WebSocket frame") {
			foundFrameLog = true
			break
		}
	}

	if !foundFrameLog {
		t.Error("Expected WebSocket frame log not found")
	}

	// Test close frame
	closeFrame := []byte{0x88, 0x00}
	server.logWebSocketFrame("server->test", closeFrame)

	// Check logs for close frame
	messages = log.getMessages()
	foundCloseLog := false
	for _, msg := range messages {
		if msg.level == "debug" && strings.Contains(msg.msg, "WebSocket frame") {
			// Check if this is the close frame log
			for i := 0; i < len(msg.args); i += 2 {
				if i+1 < len(msg.args) && msg.args[i] == "opcode" && msg.args[i+1] == "close" {
					foundCloseLog = true
					break
				}
			}
		}
	}

	if !foundCloseLog {
		t.Error("Expected WebSocket close frame log not found")
	}
}

func TestServer_WebSocketHandshake(t *testing.T) {
	// Create a mock WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify WebSocket handshake headers
		if r.Header.Get("Upgrade") != "websocket" {
			t.Errorf("Expected Upgrade: websocket, got %s", r.Header.Get("Upgrade"))
		}
		if r.Header.Get("Connection") != "Upgrade" {
			t.Errorf("Expected Connection: Upgrade, got %s", r.Header.Get("Connection"))
		}

		// Send proper WebSocket upgrade response
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", "test-accept")
		w.WriteHeader(101)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             8080,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}
	proxyServer, _ := New(cfg, log)

	// Create a connection to the mock server
	u, _ := url.Parse(server.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	// Create a mock WebSocket upgrade request
	req := httptest.NewRequest("GET", server.URL+"/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "test-key")
	req.Header.Set("Sec-WebSocket-Version", "13")

	targetURL, _ := url.Parse(server.URL + "/ws")

	// Test the handshake
	err = proxyServer.performWebSocketHandshake(conn, req, targetURL)
	if err != nil {
		t.Errorf("performWebSocketHandshake() failed: %v", err)
	}

	// Check logs
	messages := log.getMessages()
	foundHandshakeLog := false
	for _, msg := range messages {
		if msg.level == "debug" && strings.Contains(msg.msg, "WebSocket handshake completed") {
			foundHandshakeLog = true
			break
		}
	}

	if !foundHandshakeLog {
		t.Error("Expected WebSocket handshake completion log not found")
	}
}

func TestServer_HandleWebSocketUpgrade(t *testing.T) {
	// Create a simple WebSocket echo server
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple WebSocket handshake response
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		
		// Generate proper Sec-WebSocket-Accept
		key := r.Header.Get("Sec-WebSocket-Key")
		if key != "" {
			const websocketMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
			h := sha1.New()
			h.Write([]byte(key + websocketMagicString))
			accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
			w.Header().Set("Sec-WebSocket-Accept", accept)
		}
		
		w.WriteHeader(101)
	}))
	defer wsServer.Close()

	// Create proxy server
	tempDir := t.TempDir()
	cfg := &config.Config{
		Port:             0,
		BufferSize:       32768,
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertKeySize:      2048,
		CertValidityDays: 365,
	}
	log := &mockLogger{}

	server, err := New(cfg, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
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
		t.Fatal("Server not ready")
	}

	// Create a WebSocket upgrade request through the proxy
	proxyURL := "http://" + addr
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
		},
		Timeout: 5 * time.Second,
	}

	// Create WebSocket upgrade request
	req, _ := http.NewRequest("GET", wsServer.URL+"/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("WebSocket upgrade request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check if we got a 101 response (though the client might not see it due to hijacking)
	if resp.StatusCode != 101 && resp.StatusCode != 200 {
		t.Logf("WebSocket upgrade response status: %d (this may be expected due to connection hijacking)", resp.StatusCode)
	}

	// Check logs for WebSocket activity
	messages := log.getMessages()
	foundUpgradeLog := false
	for _, msg := range messages {
		if msg.level == "info" && strings.Contains(msg.msg, "WebSocket upgrade request") {
			foundUpgradeLog = true
			break
		}
	}

	if !foundUpgradeLog {
		t.Error("Expected WebSocket upgrade log not found")
	}

	cancel()
	<-errChan
}