package proxy

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/pshima/breakthru/internal/config"
	"github.com/pshima/breakthru/internal/logger"
)

func TestExtractTLSInfo(t *testing.T) {
	// Test with valid TLS ClientHello with SNI
	// This is a minimal but correctly formatted TLS 1.0 ClientHello with SNI extension
	clientHelloWithSNI := []byte{
		// TLS Record Header (5 bytes)
		0x16,       // Content Type: Handshake
		0x03, 0x01, // Version: TLS 1.0
		0x00, 0x43, // Length: 67 bytes (handshake message length = 72 - 5)
		
		// Handshake Header (4 bytes)
		0x01,       // Handshake Type: Client Hello
		0x00, 0x00, 0x3f, // Length: 63 bytes (handshake message body = 67 - 4)
		
		// Client Hello Message Body
		0x03, 0x01, // Version: TLS 1.0
		
		// Random (32 bytes) - simplified for testing
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		
		0x00, // Session ID Length: 0
		
		// Cipher Suites
		0x00, 0x02, // Cipher Suites Length: 2 bytes (1 cipher suite)
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		
		// Compression Methods  
		0x01, // Compression Methods Length: 1
		0x00, // Compression Method: null
		
		// Extensions
		0x00, 0x14, // Extensions Length: 20 bytes (4 + 16)
		
		// SNI Extension
		0x00, 0x00, // Extension Type: server_name (0)
		0x00, 0x10, // Extension Length: 16 bytes (2 + 1 + 2 + 11)
		0x00, 0x0e, // Server Name List Length: 14 bytes (1 + 2 + 11)
		0x00,       // Name Type: host_name (0)
		0x00, 0x0b, // Name Length: 11 bytes
		// "example.com" (11 bytes)
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}

	// Test TLS info extraction
	
	tlsInfo, err := extractTLSInfo(clientHelloWithSNI)
	if err != nil {
		t.Fatalf("Failed to extract TLS info: %v", err)
	}

	if tlsInfo.ServerName != "example.com" {
		t.Errorf("Expected SNI 'example.com', got '%s'", tlsInfo.ServerName)
	}

	if tlsInfo.Version != 0x0301 {
		t.Errorf("Expected TLS version 0x0301, got 0x%04x", tlsInfo.Version)
	}
}

func TestExtractTLSInfo_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"Empty data", []byte{}},
		{"Too short", []byte{0x16, 0x03}},
		{"Not TLS handshake", []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00}},
		{"Invalid TLS version", []byte{0x16, 0x02, 0xff, 0x00, 0x02, 0x01, 0x00}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := extractTLSInfo(test.data)
			if err == nil {
				t.Errorf("Expected error for %s, but got none", test.name)
			}
		})
	}
}

func TestParseSNIExtension(t *testing.T) {
	// Valid SNI extension data
	sniData := []byte{
		0x00, 0x0e, // Server name list length (14 bytes: 1 + 2 + 11)
		0x00,       // Name type (hostname)
		0x00, 0x0b, // Name length (11 bytes for "example.com")
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "example.com"
	}

	hostname, err := parseSNIExtension(sniData)
	if err != nil {
		t.Fatalf("Failed to parse SNI extension: %v", err)
	}

	if hostname != "example.com" {
		t.Errorf("Expected hostname 'example.com', got '%s'", hostname)
	}
}

func TestParseSNIExtension_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"Too short", []byte{0x00}},
		{"No hostname", []byte{0x00, 0x05, 0x01, 0x00, 0x02, 0x68, 0x69}},
		{"Invalid length", []byte{0x00, 0x10, 0x00, 0x00, 0x20, 0x73, 0x68, 0x6f, 0x72, 0x74}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSNIExtension(test.data)
			if err == nil {
				t.Errorf("Expected error for %s, but got none", test.name)
			}
		})
	}
}

func TestCreateTLSConfigForHost(t *testing.T) {
	// Setup test environment
	tempDir := t.TempDir()
	cfg := &config.Config{
		CertStoreDir:     tempDir,
		AutoGenerateCA:   true,
		CertValidityDays: 365,
		CertKeySize:      2048,
	}

	log, err := logger.New(logger.Config{
		FilePath: filepath.Join(t.TempDir(), "test.log"),
		Verbose:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer log.Close()

	// Create server with certificate components
	server := &Server{config: cfg, logger: log}
	err = server.initializeCertificates(cfg, log)
	if err != nil {
		t.Fatalf("Failed to initialize certificates: %v", err)
	}

	// Test TLS config creation
	hostname := "test.example.com"
	tlsConfig, err := server.createTLSConfigForHost(hostname)
	if err != nil {
		t.Fatalf("Failed to create TLS config: %v", err)
	}

	if tlsConfig.ServerName != hostname {
		t.Errorf("Expected ServerName '%s', got '%s'", hostname, tlsConfig.ServerName)
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestCreateClientTLSConfig(t *testing.T) {
	cfg := &config.Config{
		HTTPSSkipVerify: true,
	}

	server := &Server{config: cfg}
	hostname := "example.com"

	tlsConfig := server.createClientTLSConfig(hostname)

	if tlsConfig.ServerName != hostname {
		t.Errorf("Expected ServerName '%s', got '%s'", hostname, tlsConfig.ServerName)
	}

	if !tlsConfig.InsecureSkipVerify {
		t.Errorf("Expected InsecureSkipVerify to be true")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestIsTLSHandshake(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			"Valid TLS handshake",
			[]byte{0x16, 0x03, 0x01, 0x00, 0x9c, 0x01},
			true,
		},
		{
			"Valid TLS 1.3 handshake",
			[]byte{0x16, 0x03, 0x03, 0x00, 0x9c, 0x01},
			true,
		},
		{
			"Not TLS record",
			[]byte{0x17, 0x03, 0x01, 0x00, 0x9c, 0x01},
			false,
		},
		{
			"Invalid version",
			[]byte{0x16, 0x02, 0x01, 0x00, 0x9c, 0x01},
			false,
		},
		{
			"Too short",
			[]byte{0x16, 0x03},
			false,
		},
		{
			"Empty",
			[]byte{},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isTLSHandshake(test.data)
			if result != test.expected {
				t.Errorf("Expected %t, got %t", test.expected, result)
			}
		})
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	// This test ensures that TLS handshake operations respect timeouts
	// We'll test this by setting up a mock connection that doesn't respond

	// Create a pipe to simulate a connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Set a short timeout
	clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Try to peek TLS server name (should timeout)
	_, err := peekTLSServerName(clientConn)
	if err == nil {
		t.Errorf("Expected timeout error, but got none")
	}

	// Check that it's a timeout error
	if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func BenchmarkExtractTLSInfo(b *testing.B) {
	// Sample TLS ClientHello data
	clientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x9c,
		0x01, 0x00, 0x00, 0x98,
		0x03, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,
		0x00, 0x04, 0x00, 0x2f, 0x00, 0x35,
		0x01, 0x00,
		0x00, 0x15,
		0x00, 0x00, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x00, 0x0c,
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := extractTLSInfo(clientHello)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}