package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CAManager handles Certificate Authority operations
type CAManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certPath   string
	keyPath    string
	keySize    int
	validYears int
}

// NewCAManager creates a new CA manager instance
func NewCAManager(certPath, keyPath string) *CAManager {
	return &CAManager{
		certPath:   certPath,
		keyPath:    keyPath,
		keySize:    2048,
		validYears: 10,
	}
}

// LoadCA loads existing CA certificate and key from files
func (ca *CAManager) LoadCA() error {
	// Load CA certificate
	certData, err := os.ReadFile(ca.certPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	ca.caCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load CA private key
	keyData, err := os.ReadFile(ca.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	ca.caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return nil
}

// GenerateCA creates a new CA certificate and private key
func (ca *CAManager) GenerateCA() error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, ca.keySize)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Breakthru Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "Breakthru Proxy CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(ca.validYears, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse certificate for storage
	ca.caCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	ca.caKey = privateKey

	// Save to files
	if err := ca.SaveCA(); err != nil {
		return fmt.Errorf("failed to save CA files: %w", err)
	}

	return nil
}

// SaveCA saves the CA certificate and key to files
func (ca *CAManager) SaveCA() error {
	if ca.caCert == nil || ca.caKey == nil {
		return fmt.Errorf("no CA certificate or key loaded")
	}

	// Ensure directories exist
	certDir := filepath.Dir(ca.certPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	keyDir := filepath.Dir(ca.keyPath)
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Save certificate
	certFile, err := os.Create(ca.certPath)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCert.Raw,
	}); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Save private key with restricted permissions
	keyFile, err := os.OpenFile(ca.keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CA key file: %w", err)
	}
	defer keyFile.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(ca.caKey)
	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	return nil
}

// GetCACertificate returns the CA certificate
func (ca *CAManager) GetCACertificate() *x509.Certificate {
	return ca.caCert
}

// GetCAPrivateKey returns the CA private key
func (ca *CAManager) GetCAPrivateKey() *rsa.PrivateKey {
	return ca.caKey
}

// IsCALoaded returns true if CA certificate and key are loaded
func (ca *CAManager) IsCALoaded() bool {
	return ca.caCert != nil && ca.caKey != nil
}

// ValidateCA checks if the loaded CA certificate is valid
func (ca *CAManager) ValidateCA() error {
	if !ca.IsCALoaded() {
		return fmt.Errorf("no CA certificate loaded")
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(ca.caCert.NotBefore) {
		return fmt.Errorf("CA certificate is not yet valid (valid from: %v)", ca.caCert.NotBefore)
	}

	if now.After(ca.caCert.NotAfter) {
		return fmt.Errorf("CA certificate has expired (expired: %v)", ca.caCert.NotAfter)
	}

	// Check if it's actually a CA certificate
	if !ca.caCert.IsCA {
		return fmt.Errorf("certificate is not a CA certificate")
	}

	// Verify key usage
	if ca.caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("CA certificate does not have certificate signing capability")
	}

	return nil
}

// GetCAInfo returns information about the loaded CA certificate
func (ca *CAManager) GetCAInfo() (*CertificateInfo, error) {
	if !ca.IsCALoaded() {
		return nil, fmt.Errorf("no CA certificate loaded")
	}

	return &CertificateInfo{
		Subject:    ca.caCert.Subject.String(),
		Issuer:     ca.caCert.Issuer.String(),
		NotBefore:  ca.caCert.NotBefore,
		NotAfter:   ca.caCert.NotAfter,
		IsCA:       ca.caCert.IsCA,
		KeyUsage:   ca.caCert.KeyUsage,
		CommonName: ca.caCert.Subject.CommonName,
	}, nil
}

// CertificateInfo holds certificate information for display
type CertificateInfo struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	IsCA       bool
	KeyUsage   x509.KeyUsage
	CommonName string
}