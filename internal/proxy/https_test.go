package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pshima/breakthru/internal/config"
	"github.com/pshima/breakthru/internal/logger"
)

func TestServer_ShouldBypassHTTPS(t *testing.T) {
	cfg := &config.Config{
		HTTPSBypassDomains: []string{"example.com", "*.internal.com", "test.org"},
	}
	server := &Server{config: cfg}

	tests := []struct {
		hostname string
		expected bool
	}{
		{"example.com", true},
		{"www.example.com", false},
		{"api.internal.com", true},
		{"sub.api.internal.com", true},
		{"internal.com", true},
		{"test.org", true},
		{"google.com", false},
		{"", false},
	}

	for _, test := range tests {
		t.Run(test.hostname, func(t *testing.T) {
			result := server.shouldBypassHTTPS(test.hostname)
			if result != test.expected {
				t.Errorf("shouldBypassHTTPS(%q) = %t, expected %t", test.hostname, result, test.expected)
			}
		})
	}
}

func TestServer_ShouldInterceptHTTPS(t *testing.T) {
	tests := []struct {
		name        string
		onlyDomains []string
		hostname    string
		expected    bool
	}{
		{
			"No restrictions",
			[]string{},
			"example.com",
			true,
		},
		{
			"Exact match",
			[]string{"example.com"},
			"example.com",
			true,
		},
		{
			"No match",
			[]string{"example.com"},
			"google.com",
			false,
		},
		{
			"Wildcard match",
			[]string{"*.example.com"},
			"api.example.com",
			true,
		},
		{
			"Wildcard base domain",
			[]string{"*.example.com"},
			"example.com",
			true,
		},
		{
			"Multiple domains",
			[]string{"example.com", "test.org"},
			"test.org",
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{
				HTTPSOnlyDomains: test.onlyDomains,
			}
			server := &Server{config: cfg}

			result := server.shouldInterceptHTTPS(test.hostname)
			if result != test.expected {
				t.Errorf("shouldInterceptHTTPS(%q) = %t, expected %t", test.hostname, result, test.expected)
			}
		})
	}
}

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "sub.www.example.com", true},
		{"*.example.com", "example.org", false},
		{"test.org", "test.org", true},
		{"test.org", "api.test.org", false},
		{"", "example.com", false},
		{"example.com", "", false},
	}

	for _, test := range tests {
		t.Run(test.pattern+"_"+test.hostname, func(t *testing.T) {
			result := matchesDomain(test.pattern, test.hostname)
			if result != test.expected {
				t.Errorf("matchesDomain(%q, %q) = %t, expected %t", test.pattern, test.hostname, result, test.expected)
			}
		})
	}
}

func TestServer_HandleConnect_InterceptionDisabled(t *testing.T) {
	// Setup server with HTTPS interception disabled
	cfg := &config.Config{
		HTTPSInterception: false,
		CertStoreDir:      t.TempDir(),
		AutoGenerateCA:    true,
	}

	log, err := logger.New(logger.Config{
		FilePath: "/dev/null", // Use null device for tests
		Verbose:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer log.Close()

	server := &Server{config: cfg, logger: log}

	// Create a test server to act as the target
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from target"))
	}))
	defer targetServer.Close()

	// Extract host from target server URL
	targetURL := strings.TrimPrefix(targetServer.URL, "https://")

	// Create HTTP test request
	req := httptest.NewRequest("CONNECT", "http://proxy", nil)
	req.Host = targetURL

	// Create custom response writer that supports hijacking
	recorder := &hijackableRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		clientConn:       &mockConn{},
		serverConn:       &mockConn{},
	}

	// Call handleConnect
	server.handleConnect(recorder, req)

	// Since interception is disabled, this should attempt to create a tunnel
	// We can't easily test the full tunnel behavior in a unit test,
	// but we can verify the method completes without error
}

func TestServer_HandleConnect_DomainBypassed(t *testing.T) {
	cfg := &config.Config{
		HTTPSInterception:  true,
		HTTPSBypassDomains: []string{"bypass.com"},
		CertStoreDir:       t.TempDir(),
		AutoGenerateCA:     true,
	}

	log, err := logger.New(logger.Config{
		FilePath: "/dev/null", // Use null device for tests
		Verbose:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer log.Close()

	server := &Server{config: cfg, logger: log}

	req := httptest.NewRequest("CONNECT", "http://proxy", nil)
	req.Host = "bypass.com:443"

	recorder := &hijackableRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		clientConn:       &mockConn{},
		serverConn:       &mockConn{},
	}

	server.handleConnect(recorder, req)

	// Should bypass interception and create tunnel
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0400, "Unknown (0x0400)"},
		{0x0000, "Unknown (0x0000)"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := tlsVersionString(test.version)
			if result != test.expected {
				t.Errorf("tlsVersionString(0x%04x) = %q, expected %q", test.version, result, test.expected)
			}
		})
	}
}

func TestServer_InitializeCertificates(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		CertStoreDir:       tempDir,
		AutoGenerateCA:     true,
		CertValidityDays:   365,
		CertKeySize:        2048,
		CertCleanupEnabled: true,
	}

	log, err := logger.New(logger.Config{
		FilePath: "/dev/null", // Use null device for tests
		Verbose:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer log.Close()

	server := &Server{config: cfg, logger: log}

	err = server.initializeCertificates(cfg, log)
	if err != nil {
		t.Fatalf("Failed to initialize certificates: %v", err)
	}

	// Verify components are initialized
	if server.caManager == nil {
		t.Error("CA manager not initialized")
	}

	if server.certGenerator == nil {
		t.Error("Certificate generator not initialized")
	}

	if server.certStore == nil {
		t.Error("Certificate store not initialized")
	}

	// Verify CA is loaded
	if !server.caManager.IsCALoaded() {
		t.Error("CA should be loaded after initialization")
	}

	// Verify CA validation passes
	if err := server.caManager.ValidateCA(); err != nil {
		t.Errorf("CA validation failed: %v", err)
	}
}

func TestServer_InitializeCertificates_NoAutoGenerate(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		CertStoreDir:   tempDir,
		AutoGenerateCA: false, // Disabled
		CACert:         "",    // No existing CA
		CAKey:          "",
	}

	log, err := logger.New(logger.Config{
		FilePath: "/dev/null", // Use null device for tests
		Verbose:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer log.Close()

	server := &Server{config: cfg, logger: log}

	err = server.initializeCertificates(cfg, log)
	if err == nil {
		t.Error("Expected error when CA not found and auto-generation disabled")
	}

	if !strings.Contains(err.Error(), "auto-generation is disabled") {
		t.Errorf("Expected auto-generation disabled error, got: %v", err)
	}
}

// Mock implementations for testing

type hijackableRecorder struct {
	*httptest.ResponseRecorder
	clientConn net.Conn
	serverConn net.Conn
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.clientConn, nil, nil
}

type mockConn struct {
	net.Conn
	readData  []byte
	writeData []byte
	closed    bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if len(m.readData) == 0 {
		return 0, net.ErrClosed
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, net.ErrClosed
	}
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// Integration test for full HTTPS interception flow
func TestHTTPSInterception_Integration(t *testing.T) {
	// This test is more complex and would require setting up actual TLS connections
	// For now, we'll skip it in unit tests and handle it in integration tests
	t.Skip("Integration test - requires full TLS setup")

	// In a full integration test, this would:
	// 1. Start the proxy server with HTTPS interception enabled
	// 2. Configure a test client to use the proxy
	// 3. Install the CA certificate in the client
	// 4. Make HTTPS requests through the proxy
	// 5. Verify that requests/responses are logged in plaintext
	// 6. Verify that the target server receives the requests correctly
}

func BenchmarkShouldBypassHTTPS(b *testing.B) {
	cfg := &config.Config{
		HTTPSBypassDomains: []string{
			"example.com", "*.internal.com", "test.org",
			"api.service.com", "*.dev.local", "staging.app.com",
		},
	}
	server := &Server{config: cfg}

	hostnames := []string{
		"example.com", "api.internal.com", "test.org",
		"google.com", "facebook.com", "github.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostname := hostnames[i%len(hostnames)]
		server.shouldBypassHTTPS(hostname)
	}
}

func BenchmarkShouldInterceptHTTPS(b *testing.B) {
	cfg := &config.Config{
		HTTPSOnlyDomains: []string{
			"*.game.com", "api.service.com", "*.analytics.com",
		},
	}
	server := &Server{config: cfg}

	hostnames := []string{
		"client.game.com", "api.service.com", "track.analytics.com",
		"example.com", "google.com", "facebook.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostname := hostnames[i%len(hostnames)]
		server.shouldInterceptHTTPS(hostname)
	}
}