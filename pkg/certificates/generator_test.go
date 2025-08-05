package certificates

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateGenerator_GenerateCertificate(t *testing.T) {
	// Setup CA
	tempDir, err := os.MkdirTemp("", "gen_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Test certificate generation
	domains := []string{"example.com", "www.example.com"}
	cert, err := generator.GenerateCertificate(domains)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Verify certificate properties
	if cert.Certificate.Subject.CommonName != "example.com" {
		t.Errorf("Unexpected common name: %s", cert.Certificate.Subject.CommonName)
	}

	if len(cert.Certificate.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(cert.Certificate.DNSNames))
	}

	if cert.Certificate.DNSNames[0] != "example.com" || cert.Certificate.DNSNames[1] != "www.example.com" {
		t.Errorf("Unexpected DNS names: %v", cert.Certificate.DNSNames)
	}

	if cert.Certificate.IsCA {
		t.Errorf("Generated certificate should not be marked as CA")
	}

	// Verify certificate is signed by CA
	caCert := caManager.GetCACertificate()
	if cert.Certificate.Issuer.CommonName != caCert.Subject.CommonName {
		t.Errorf("Certificate not signed by expected CA")
	}
}

func TestCertificateGenerator_GenerateCertificateForHost(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gen_host_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Test single host
	cert, err := generator.GenerateCertificateForHost("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate for host: %v", err)
	}

	if !cert.IsValidForHost("test.example.com") {
		t.Errorf("Certificate should be valid for test.example.com")
	}

	// Test host with port (should be stripped)
	cert2, err := generator.GenerateCertificateForHost("api.example.com:8080")
	if err != nil {
		t.Fatalf("Failed to generate certificate for host with port: %v", err)
	}

	if !cert2.IsValidForHost("api.example.com") {
		t.Errorf("Certificate should be valid for api.example.com")
	}
}

func TestCertificateGenerator_GenerateWildcardCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gen_wildcard_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Test wildcard certificate
	cert, err := generator.GenerateWildcardCertificate("example.com")
	if err != nil {
		t.Fatalf("Failed to generate wildcard certificate: %v", err)
	}

	// Should have both wildcard and domain
	expectedDNSNames := []string{"*.example.com", "example.com"}
	if len(cert.Certificate.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(cert.Certificate.DNSNames))
	}

	for i, expected := range expectedDNSNames {
		if cert.Certificate.DNSNames[i] != expected {
			t.Errorf("Expected DNS name %d to be %s, got %s", i, expected, cert.Certificate.DNSNames[i])
		}
	}

	// Test validity for various hosts
	validHosts := []string{"example.com", "www.example.com", "api.example.com", "sub.example.com"}
	for _, host := range validHosts {
		if !cert.IsValidForHost(host) {
			t.Errorf("Wildcard certificate should be valid for %s", host)
		}
	}

	// Test invalid hosts
	invalidHosts := []string{"example.org", "sub.sub.example.com", "notexample.com"}
	for _, host := range invalidHosts {
		if cert.IsValidForHost(host) {
			t.Errorf("Wildcard certificate should NOT be valid for %s", host)
		}
	}
}

func TestCertificateGenerator_IPAddresses(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gen_ip_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Test certificate with IP addresses
	domains := []string{"192.168.1.1", "127.0.0.1", "example.com"}
	cert, err := generator.GenerateCertificate(domains)
	if err != nil {
		t.Fatalf("Failed to generate certificate with IPs: %v", err)
	}

	// Should have 2 IP addresses and 1 DNS name
	if len(cert.Certificate.IPAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(cert.Certificate.IPAddresses))
	}

	if len(cert.Certificate.DNSNames) != 1 {
		t.Errorf("Expected 1 DNS name, got %d", len(cert.Certificate.DNSNames))
	}

	// Verify specific IPs
	expectedIPs := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("127.0.0.1")}
	for i, expectedIP := range expectedIPs {
		if !cert.Certificate.IPAddresses[i].Equal(expectedIP) {
			t.Errorf("Expected IP %d to be %s, got %s", i, expectedIP, cert.Certificate.IPAddresses[i])
		}
	}

	// Test validity
	if !cert.IsValidForHost("192.168.1.1") {
		t.Errorf("Certificate should be valid for IP 192.168.1.1")
	}

	if !cert.IsValidForHost("example.com") {
		t.Errorf("Certificate should be valid for domain example.com")
	}
}

func TestGeneratedCertificate_ToPEM(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gen_pem_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	cert, err := generator.GenerateCertificateForHost("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	certPEM, keyPEM, err := cert.ToPEM()
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	// Verify PEM format
	if len(certPEM) == 0 {
		t.Errorf("Certificate PEM is empty")
	}

	if len(keyPEM) == 0 {
		t.Errorf("Key PEM is empty")
	}

	// Verify we can parse the PEM back
	parsedCert, parsedKey, err := ParseCertificateAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse generated PEM: %v", err)
	}

	if !parsedCert.Equal(cert.Certificate) {
		t.Errorf("Parsed certificate does not match original")
	}

	if parsedKey.N.Cmp(cert.PrivateKey.N) != 0 {
		t.Errorf("Parsed private key does not match original")
	}
}

func TestGeneratedCertificate_IsExpired(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gen_expire_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Set short validity period for testing
	generator.SetValidityPeriod(1) // 1 day

	cert, err := generator.GenerateCertificateForHost("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Should not be expired initially
	if cert.IsExpired() {
		t.Errorf("Newly generated certificate should not be expired")
	}

	// Should expire within 2 days (includes buffer)
	if !cert.ExpiresWithin(2 * 24 * time.Hour) {
		t.Errorf("Certificate should expire within 2 days")
	}
}

func TestCertificateGenerator_SetKeySize(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gen_keysize_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Test invalid key size
	err = generator.SetKeySize(512)
	if err == nil {
		t.Errorf("Should reject key size smaller than 1024")
	}

	// Test valid key size
	err = generator.SetKeySize(1024)
	if err != nil {
		t.Errorf("Should accept key size 1024: %v", err)
	}

	// Generate certificate and verify key size
	cert, err := generator.GenerateCertificateForHost("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if cert.PrivateKey.N.BitLen() != 1024 {
		t.Errorf("Expected key size 1024, got %d", cert.PrivateKey.N.BitLen())
	}
}

func TestMatchesDNSName(t *testing.T) {
	tests := []struct {
		dnsName string
		host    string
		matches bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", true}, // wildcard matches base domain
		{"*.example.com", "sub.www.example.com", false}, // wildcard doesn't match multiple levels
		{"*.example.com", "example.org", false},
		{"test.example.com", "test.example.com", true},
		{"test.example.com", "example.com", false},
	}

	for _, test := range tests {
		result := matchesDNSName(test.dnsName, test.host)
		if result != test.matches {
			t.Errorf("matchesDNSName(%q, %q) = %t, expected %t", test.dnsName, test.host, result, test.matches)
		}
	}
}

// Helper function to setup a test CA
func setupTestCA(t *testing.T, tempDir string) *CAManager {
	certPath := filepath.Join(tempDir, "test_ca.crt")
	keyPath := filepath.Join(tempDir, "test_ca.key")

	caManager := NewCAManager(certPath, keyPath)
	err := caManager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate test CA: %v", err)
	}

	return caManager
}