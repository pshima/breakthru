package certificates

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseCertificateAndKey(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "utils_parse_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate a test certificate
	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	
	originalCert, err := generator.GenerateCertificateForHost("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Convert to PEM
	certPEM, keyPEM, err := originalCert.ToPEM()
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	// Parse back
	parsedCert, parsedKey, err := ParseCertificateAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse certificate and key: %v", err)
	}

	// Verify parsed certificate matches original
	if !parsedCert.Equal(originalCert.Certificate) {
		t.Errorf("Parsed certificate does not match original")
	}

	// Verify parsed key matches original
	if parsedKey.N.Cmp(originalCert.PrivateKey.N) != 0 {
		t.Errorf("Parsed private key does not match original")
	}
}

func TestParseCertificateAndKey_InvalidData(t *testing.T) {
	// Test with invalid certificate PEM
	_, _, err := ParseCertificateAndKey([]byte("invalid cert data"), []byte("-----BEGIN RSA PRIVATE KEY-----\nvalid key data\n-----END RSA PRIVATE KEY-----"))
	if err == nil {
		t.Errorf("Should fail with invalid certificate PEM")
	}

	// Test with invalid key PEM
	validCertPEM := []byte("-----BEGIN CERTIFICATE-----\nvalid cert data\n-----END CERTIFICATE-----")
	_, _, err = ParseCertificateAndKey(validCertPEM, []byte("invalid key data"))
	if err == nil {
		t.Errorf("Should fail with invalid key PEM")
	}
}

func TestLoadCertificateFromFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "utils_load_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate and save a test certificate
	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	
	originalCert, err := generator.GenerateCertificateForHost("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	certPEM, _, err := originalCert.ToPEM()
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	certPath := filepath.Join(tempDir, "test.crt")
	err = os.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	// Load certificate from file
	loadedCert, err := LoadCertificateFromFile(certPath)
	if err != nil {
		t.Fatalf("Failed to load certificate from file: %v", err)
	}

	// Verify loaded certificate matches original
	if !loadedCert.Equal(originalCert.Certificate) {
		t.Errorf("Loaded certificate does not match original")
	}
}

func TestLoadCertificateFromFile_NonExistent(t *testing.T) {
	_, err := LoadCertificateFromFile("/nonexistent/path/cert.pem")
	if err == nil {
		t.Errorf("Should fail when loading non-existent file")
	}
}

func TestFormatCertificateInfo(t *testing.T) {
	info := &CertificateInfo{
		Subject:    "CN=test.example.com,O=Test Org",
		Issuer:     "CN=Test CA,O=Test CA Org",
		NotBefore:  time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:       false,
		KeyUsage:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		CommonName: "test.example.com",
	}

	formatted := FormatCertificateInfo(info)

	// Check that all expected information is present
	expectedStrings := []string{
		"Subject: CN=test.example.com,O=Test Org",
		"Issuer: CN=Test CA,O=Test CA Org",
		"Common Name: test.example.com",
		"Is CA: false",
		"Digital Signature",
		"Key Encipherment",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(formatted, expected) {
			t.Errorf("Formatted output should contain: %s\nActual output:\n%s", expected, formatted)
		}
	}
}

func TestFormatCertificateInfo_ExpiredCert(t *testing.T) {
	// Create an expired certificate info
	info := &CertificateInfo{
		Subject:    "CN=expired.example.com",
		Issuer:     "CN=Test CA",
		NotBefore:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:   time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), // Expired
		IsCA:       false,
		KeyUsage:   x509.KeyUsageDigitalSignature,
		CommonName: "expired.example.com",
	}

	formatted := FormatCertificateInfo(info)

	if !strings.Contains(formatted, "Status: EXPIRED") {
		t.Errorf("Should indicate certificate is expired")
	}
}

func TestFormatCertificateInfo_NotYetValid(t *testing.T) {
	// Create a future certificate info
	futureTime := time.Now().Add(24 * time.Hour)
	info := &CertificateInfo{
		Subject:    "CN=future.example.com",
		Issuer:     "CN=Test CA",
		NotBefore:  futureTime,
		NotAfter:   futureTime.Add(365 * 24 * time.Hour),
		IsCA:       false,
		KeyUsage:   x509.KeyUsageDigitalSignature,
		CommonName: "future.example.com",
	}

	formatted := FormatCertificateInfo(info)

	if !strings.Contains(formatted, "Status: Not yet valid") {
		t.Errorf("Should indicate certificate is not yet valid")
	}
}

func TestIsCertificateValidForHost(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "utils_valid_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Test regular certificate
	cert, err := generator.GenerateCertificate([]string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	tests := []struct {
		host    string
		valid   bool
		message string
	}{
		{"example.com", true, "should be valid for exact match"},
		{"www.example.com", true, "should be valid for DNS name"},
		{"example.com:8080", true, "should be valid for host with port"},
		{"api.example.com", false, "should not be valid for subdomain not in DNS names"},
		{"example.org", false, "should not be valid for different domain"},
	}

	for _, test := range tests {
		result := IsCertificateValidForHost(cert.Certificate, test.host)
		if result != test.valid {
			t.Errorf("IsCertificateValidForHost(%q) = %t, expected %t: %s", 
				test.host, result, test.valid, test.message)
		}
	}
}

func TestIsCertificateValidForHost_Wildcard(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "utils_wildcard_test")
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

	tests := []struct {
		host    string
		valid   bool
		message string
	}{
		{"example.com", true, "wildcard should match base domain"},
		{"www.example.com", true, "wildcard should match subdomain"},
		{"api.example.com", true, "wildcard should match any subdomain"},
		{"sub.sub.example.com", false, "wildcard should not match multiple levels"},
		{"example.org", false, "wildcard should not match different domain"},
	}

	for _, test := range tests {
		result := IsCertificateValidForHost(cert.Certificate, test.host)
		if result != test.valid {
			t.Errorf("IsCertificateValidForHost(%q) = %t, expected %t: %s", 
				test.host, result, test.valid, test.message)
		}
	}
}

func TestIsCertificateValidForHost_IPAddress(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "utils_ip_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)

	// Test certificate with IP addresses
	cert, err := generator.GenerateCertificate([]string{"192.168.1.1", "127.0.0.1"})
	if err != nil {
		t.Fatalf("Failed to generate certificate with IPs: %v", err)
	}

	tests := []struct {
		host    string
		valid   bool
		message string
	}{
		{"192.168.1.1", true, "should be valid for exact IP match"},
		{"127.0.0.1", true, "should be valid for exact IP match"},
		{"192.168.1.2", false, "should not be valid for different IP"},
		{"example.com", false, "should not be valid for domain when only IPs present"},
	}

	for _, test := range tests {
		result := IsCertificateValidForHost(cert.Certificate, test.host)
		if result != test.valid {
			t.Errorf("IsCertificateValidForHost(%q) = %t, expected %t: %s", 
				test.host, result, test.valid, test.message)
		}
	}
}

// Platform-specific tests - these will be skipped if the platform tools aren't available
func TestInstallCACertificate_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	tempDir, err := os.MkdirTemp("", "utils_install_win_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	certPath := filepath.Join(tempDir, "test_ca.crt")

	// Save CA certificate to file
	if err := caManager.SaveCA(); err != nil {
		t.Fatalf("Failed to save CA: %v", err)
	}

	// Test installation (this will likely fail in CI/test environment without admin rights)
	err = InstallCACertificate(certPath)
	if err != nil {
		t.Logf("CA installation failed (expected in test environment): %v", err)
		// Don't fail the test as this typically requires admin rights
	}
}

func TestInstallCACertificate_UnsupportedOS(t *testing.T) {
	// This test will pass on supported platforms and fail with appropriate error on unsupported ones
	tempDir, err := os.MkdirTemp("", "utils_install_unsupported_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fakeCertPath := filepath.Join(tempDir, "fake.crt")
	err = os.WriteFile(fakeCertPath, []byte("fake certificate data"), 0644)
	if err != nil {
		t.Fatalf("Failed to create fake certificate file: %v", err)
	}

	err = InstallCACertificate(fakeCertPath)
	// On supported platforms, this might fail due to invalid certificate format
	// On unsupported platforms, it should fail with "not supported" error
	if err != nil && !strings.Contains(err.Error(), "not supported") && 
	   !strings.Contains(err.Error(), "failed to install") {
		t.Errorf("Unexpected error type: %v", err)
	}
}

func TestGetCertificateFingerprint(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "utils_fingerprint_test")
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

	fingerprint := GetCertificateFingerprint(cert.Certificate)

	// Fingerprint should be a hex string
	if len(fingerprint) == 0 {
		t.Errorf("Fingerprint should not be empty")
	}

	// Should be consistent
	fingerprint2 := GetCertificateFingerprint(cert.Certificate)
	if fingerprint != fingerprint2 {
		t.Errorf("Fingerprint should be consistent")
	}

	// Different certificates should have different fingerprints
	cert2, err := generator.GenerateCertificateForHost("other.example.com")
	if err != nil {
		t.Fatalf("Failed to generate second certificate: %v", err)
	}

	fingerprint3 := GetCertificateFingerprint(cert2.Certificate)
	if fingerprint == fingerprint3 {
		t.Errorf("Different certificates should have different fingerprints")
	}
}