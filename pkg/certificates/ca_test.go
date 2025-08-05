package certificates

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCAManager_GenerateCA(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "ca_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	caManager := NewCAManager(certPath, keyPath)

	// Test CA generation
	err = caManager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("CA certificate file was not created")
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("CA key file was not created")
	}

	// Verify CA is loaded
	if !caManager.IsCALoaded() {
		t.Errorf("CA should be loaded after generation")
	}

	// Verify CA certificate properties
	cert := caManager.GetCACertificate()
	if cert == nil {
		t.Fatalf("CA certificate is nil")
	}

	if !cert.IsCA {
		t.Errorf("Generated certificate is not marked as CA")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("CA certificate does not have certificate signing capability")
	}

	if cert.Subject.CommonName != "Breakthru Proxy CA" {
		t.Errorf("Unexpected CA common name: %s", cert.Subject.CommonName)
	}
}

func TestCAManager_LoadCA(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "ca_load_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	// First generate a CA
	caManager1 := NewCAManager(certPath, keyPath)
	err = caManager1.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Create new manager and load existing CA
	caManager2 := NewCAManager(certPath, keyPath)
	err = caManager2.LoadCA()
	if err != nil {
		t.Fatalf("Failed to load CA: %v", err)
	}

	// Verify loaded CA
	if !caManager2.IsCALoaded() {
		t.Errorf("CA should be loaded")
	}

	cert1 := caManager1.GetCACertificate()
	cert2 := caManager2.GetCACertificate()

	if !cert1.Equal(cert2) {
		t.Errorf("Loaded CA certificate does not match original")
	}
}

func TestCAManager_ValidateCA(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ca_validate_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	caManager := NewCAManager(certPath, keyPath)

	// Test validation without loaded CA
	err = caManager.ValidateCA()
	if err == nil {
		t.Errorf("Validation should fail when no CA is loaded")
	}

	// Generate and validate CA
	err = caManager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	err = caManager.ValidateCA()
	if err != nil {
		t.Errorf("CA validation failed: %v", err)
	}
}

func TestCAManager_GetCAInfo(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ca_info_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	caManager := NewCAManager(certPath, keyPath)
	err = caManager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	info, err := caManager.GetCAInfo()
	if err != nil {
		t.Fatalf("Failed to get CA info: %v", err)
	}

	if info.CommonName != "Breakthru Proxy CA" {
		t.Errorf("Unexpected common name: %s", info.CommonName)
	}

	if !info.IsCA {
		t.Errorf("Certificate should be marked as CA")
	}

	if info.NotAfter.Before(time.Now()) {
		t.Errorf("CA certificate should not be expired")
	}
}

func TestCAManager_FilePermissions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ca_perms_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	caManager := NewCAManager(certPath, keyPath)
	err = caManager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Check certificate file permissions (should be readable by all)
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Failed to stat certificate file: %v", err)
	}

	// Check key file permissions (should be readable only by owner)
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}

	// Key file should have restricted permissions (0600)
	if keyInfo.Mode() != 0600 {
		t.Errorf("Key file has incorrect permissions: %o, expected 0600", keyInfo.Mode())
	}

	// Certificate file should be readable (0644)
	if certInfo.Mode() != 0644 {
		t.Errorf("Certificate file has incorrect permissions: %o, expected 0644", certInfo.Mode())
	}
}