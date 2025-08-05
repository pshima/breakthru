package certificates

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateStore_GetCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Setup CA and generator
	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)
	storeDir := filepath.Join(tempDir, "certs")
	store := NewCertificateStore(storeDir, generator)

	// Test getting certificate (should generate new one)
	cert1, err := store.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	if !cert1.IsValidForHost("example.com") {
		t.Errorf("Certificate should be valid for example.com")
	}

	// Test getting same certificate again (should use cache)
	cert2, err := store.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("Failed to get cached certificate: %v", err)
	}

	if !cert1.Certificate.Equal(cert2.Certificate) {
		t.Errorf("Should return same certificate from cache")
	}

	// Verify certificate files were created
	certPath := filepath.Join(storeDir, "example.com.crt")
	keyPath := filepath.Join(storeDir, "example.com.key")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file should be created")
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Key file should be created")
	}
}

func TestCertificateStore_GetWildcardCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_wildcard_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)
	storeDir := filepath.Join(tempDir, "certs")
	store := NewCertificateStore(storeDir, generator)

	cert, err := store.GetWildcardCertificate("example.com")
	if err != nil {
		t.Fatalf("Failed to get wildcard certificate: %v", err)
	}

	// Should be valid for subdomain and domain itself
	if !cert.IsValidForHost("www.example.com") {
		t.Errorf("Wildcard certificate should be valid for www.example.com")
	}

	if !cert.IsValidForHost("example.com") {
		t.Errorf("Wildcard certificate should be valid for example.com")
	}

	// Verify files were created with correct names
	certPath := filepath.Join(storeDir, "wildcard.example.com.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Wildcard certificate file should be created")
	}
}

func TestCertificateStore_PreloadCertificates(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_preload_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)
	storeDir := filepath.Join(tempDir, "certs")

	// Create first store and generate some certificates
	store1 := NewCertificateStore(storeDir, generator)
	_, err = store1.GetCertificate("test1.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	_, err = store1.GetCertificate("test2.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create new store and preload certificates
	store2 := NewCertificateStore(storeDir, generator)
	err = store2.PreloadCertificates()
	if err != nil {
		t.Fatalf("Failed to preload certificates: %v", err)
	}

	// Check that certificates were loaded into cache
	stats := store2.GetCacheStats()
	if stats.TotalCertificates < 2 {
		t.Errorf("Expected at least 2 certificates to be preloaded, got %d", stats.TotalCertificates)
	}

	// Verify certificates are accessible
	entries := store2.ListCertificates()
	hostFound := false
	for _, entry := range entries {
		if entry.Host == "test1.com" {
			hostFound = true
			break
		}
	}

	if !hostFound {
		t.Errorf("test1.com certificate should be in preloaded certificates")
	}
}

func TestCertificateStore_CleanupExpired(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_cleanup_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)

	// Set very short validity period to create expired certificates
	generator.SetValidityPeriod(0) // This should create immediately expired certs

	storeDir := filepath.Join(tempDir, "certs")
	store := NewCertificateStore(storeDir, generator)

	// Generate a certificate that will be expired
	cert, err := store.GetCertificate("expired.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Manually mark certificate as expired by modifying its NotAfter
	cert.Certificate.NotAfter = time.Now().Add(-time.Hour)

	// Update cache with expired certificate
	store.cache["expired.com"] = cert

	initialStats := store.GetCacheStats()
	if initialStats.TotalCertificates == 0 {
		t.Fatalf("Should have at least one certificate before cleanup")
	}

	// Run cleanup
	err = store.CleanupExpired()
	if err != nil {
		t.Fatalf("Failed to cleanup expired certificates: %v", err)
	}

	// Check that expired certificates were removed
	finalStats := store.GetCacheStats()
	if finalStats.ExpiredCertificates > 0 {
		t.Errorf("Should have no expired certificates after cleanup, got %d", finalStats.ExpiredCertificates)
	}
}

func TestCertificateStore_GetCacheStats(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_stats_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)
	storeDir := filepath.Join(tempDir, "certs")
	store := NewCertificateStore(storeDir, generator)

	// Generate some certificates
	hosts := []string{"test1.com", "test2.com", "test3.com"}
	for _, host := range hosts {
		_, err := store.GetCertificate(host)
		if err != nil {
			t.Fatalf("Failed to generate certificate for %s: %v", host, err)
		}
	}

	stats := store.GetCacheStats()
	if stats.TotalCertificates != len(hosts) {
		t.Errorf("Expected %d total certificates, got %d", len(hosts), stats.TotalCertificates)
	}

	// All certificates should be valid (not expired)
	if stats.ExpiredCertificates != 0 {
		t.Errorf("Expected 0 expired certificates, got %d", stats.ExpiredCertificates)
	}
}

func TestCertificateStore_ListCertificates(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_list_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)
	storeDir := filepath.Join(tempDir, "certs")
	store := NewCertificateStore(storeDir, generator)

	// Generate certificates
	hosts := []string{"example.com", "test.org", "api.service.com"}
	for _, host := range hosts {
		_, err := store.GetCertificate(host)
		if err != nil {
			t.Fatalf("Failed to generate certificate for %s: %v", host, err)
		}
	}

	entries := store.ListCertificates()
	if len(entries) != len(hosts) {
		t.Errorf("Expected %d certificate entries, got %d", len(hosts), len(entries))
	}

	// Verify all hosts are present
	hostMap := make(map[string]bool)
	for _, entry := range entries {
		hostMap[entry.Host] = true

		// Verify entry properties
		if entry.NotBefore.IsZero() {
			t.Errorf("Certificate entry should have NotBefore set")
		}

		if entry.NotAfter.IsZero() {
			t.Errorf("Certificate entry should have NotAfter set")
		}

		if entry.GeneratedAt.IsZero() {
			t.Errorf("Certificate entry should have GeneratedAt set")
		}
	}

	for _, host := range hosts {
		if !hostMap[host] {
			t.Errorf("Host %s should be in certificate list", host)
		}
	}
}

func TestCertificateStore_FilenameSafe(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_filename_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)
	storeDir := filepath.Join(tempDir, "certs")
	store := NewCertificateStore(storeDir, generator)

	// Test with wildcard domain
	cert, err := store.GetWildcardCertificate("example.com")
	if err != nil {
		t.Fatalf("Failed to generate wildcard certificate: %v", err)
	}

	// Verify files were created with safe names
	safeFilename := "wildcard.example.com"
	certPath := filepath.Join(storeDir, safeFilename+".crt")
	keyPath := filepath.Join(storeDir, safeFilename+".key")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file with safe name should exist: %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Key file with safe name should exist: %s", keyPath)
	}

	// Verify the certificate is still valid
	if !cert.IsValidForHost("www.example.com") {
		t.Errorf("Wildcard certificate should still be valid after filename conversion")
	}
}

func TestCertificateStore_HostWithPort(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "store_port_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caManager := setupTestCA(t, tempDir)
	generator := NewCertificateGenerator(caManager)
	// Use smaller key size for faster tests
	generator.SetKeySize(1024)
	storeDir := filepath.Join(tempDir, "certs")
	store := NewCertificateStore(storeDir, generator)

	// Request certificate for host with port
	cert, err := store.GetCertificate("example.com:8080")
	if err != nil {
		t.Fatalf("Failed to get certificate for host with port: %v", err)
	}

	// Should be valid for host without port
	if !cert.IsValidForHost("example.com") {
		t.Errorf("Certificate should be valid for example.com (without port)")
	}

	// Should also be valid for host with port
	if !cert.IsValidForHost("example.com:8080") {
		t.Errorf("Certificate should be valid for example.com:8080 (with port)")
	}

	// Verify file was created with clean hostname
	certPath := filepath.Join(storeDir, "example.com.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file should be created with clean hostname")
	}
}