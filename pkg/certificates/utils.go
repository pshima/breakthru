package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ParseCertificateAndKey parses PEM-encoded certificate and private key data
func ParseCertificateAndKey(certData, keyData []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Parse certificate
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return cert, key, nil
}

// LoadCertificateFromFile loads a certificate from a PEM file
func LoadCertificateFromFile(certPath string) (*x509.Certificate, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// ValidateCertificateChain validates a certificate chain
func ValidateCertificateChain(cert *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool) error {
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}

	// Add intermediate certificates
	for _, intermediate := range intermediates {
		opts.Intermediates.AddCert(intermediate)
	}

	_, err := cert.Verify(opts)
	return err
}

// GetCertificateFingerprint returns the SHA-256 fingerprint of a certificate
func GetCertificateFingerprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", cert.Raw)
}

// FormatCertificateInfo returns a formatted string with certificate information
func FormatCertificateInfo(info *CertificateInfo) string {
	var builder strings.Builder
	
	builder.WriteString(fmt.Sprintf("Subject: %s\n", info.Subject))
	builder.WriteString(fmt.Sprintf("Issuer: %s\n", info.Issuer))
	builder.WriteString(fmt.Sprintf("Common Name: %s\n", info.CommonName))
	builder.WriteString(fmt.Sprintf("Valid From: %s\n", info.NotBefore.Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("Valid Until: %s\n", info.NotAfter.Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("Is CA: %t\n", info.IsCA))
	
	// Format key usage
	var keyUsages []string
	if info.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, "Digital Signature")
	}
	if info.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, "Key Encipherment")
	}
	if info.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsages = append(keyUsages, "Certificate Sign")
	}
	if info.KeyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsages = append(keyUsages, "CRL Sign")
	}
	
	if len(keyUsages) > 0 {
		builder.WriteString(fmt.Sprintf("Key Usage: %s\n", strings.Join(keyUsages, ", ")))
	}
	
	// Check expiration status
	now := time.Now()
	if now.Before(info.NotBefore) {
		builder.WriteString("Status: Not yet valid\n")
	} else if now.After(info.NotAfter) {
		builder.WriteString("Status: EXPIRED\n")
	} else {
		daysUntilExpiry := int(info.NotAfter.Sub(now).Hours() / 24)
		builder.WriteString(fmt.Sprintf("Status: Valid (%d days remaining)\n", daysUntilExpiry))
	}
	
	return builder.String()
}

// InstallCACertificate installs a CA certificate in the system trust store
func InstallCACertificate(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		return installCACertWindows(certPath)
	case "darwin":
		return installCACertMacOS(certPath)
	case "linux":
		return installCACertLinux(certPath)
	default:
		return fmt.Errorf("CA certificate installation not supported on %s", runtime.GOOS)
	}
}

// UninstallCACertificate removes a CA certificate from the system trust store
func UninstallCACertificate(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		return uninstallCACertWindows(certPath)
	case "darwin":
		return uninstallCACertMacOS(certPath)
	case "linux":
		return uninstallCACertLinux(certPath)
	default:
		return fmt.Errorf("CA certificate uninstallation not supported on %s", runtime.GOOS)
	}
}

// CheckTLSConnection tests TLS connection to a host using the given certificate
func CheckTLSConnection(host string, port int, cert *x509.Certificate) error {
	address := fmt.Sprintf("%s:%d", host, port)
	
	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We'll verify manually
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()
	
	// Get peer certificates
	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return fmt.Errorf("no peer certificates found")
	}
	
	// Check if our certificate matches
	if !cert.Equal(peerCerts[0]) {
		return fmt.Errorf("certificate mismatch")
	}
	
	return nil
}

// GenerateRandomSerialNumber generates a random serial number for certificates
func GenerateRandomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// IsCertificateValidForHost checks if a certificate is valid for the given host
func IsCertificateValidForHost(cert *x509.Certificate, host string) bool {
	// Clean the host (remove port if present)
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	
	// Check DNS names
	for _, dnsName := range cert.DNSNames {
		if matchesDNSName(dnsName, host) {
			return true
		}
	}
	
	// Check IP addresses
	if ip := net.ParseIP(host); ip != nil {
		for _, certIP := range cert.IPAddresses {
			if ip.Equal(certIP) {
				return true
			}
		}
	}
	
	// Check common name as fallback (deprecated but still used)
	if cert.Subject.CommonName != "" {
		if matchesDNSName(cert.Subject.CommonName, host) {
			return true
		}
	}
	
	return false
}

// Platform-specific CA installation functions

// installCACertWindows installs CA certificate on Windows
func installCACertWindows(certPath string) error {
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	cmd := exec.Command("certutil", "-addstore", "-f", "Root", absPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install CA certificate: %w", err)
	}
	
	return nil
}

// uninstallCACertWindows removes CA certificate on Windows
func uninstallCACertWindows(certPath string) error {
	// Load certificate to get its thumbprint
	cert, err := LoadCertificateFromFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	
	thumbprint := fmt.Sprintf("%x", cert.Raw)
	cmd := exec.Command("certutil", "-delstore", "Root", thumbprint)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to uninstall CA certificate: %w", err)
	}
	
	return nil
}

// installCACertMacOS installs CA certificate on macOS
func installCACertMacOS(certPath string) error {
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", absPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install CA certificate: %w", err)
	}
	
	return nil
}

// uninstallCACertMacOS removes CA certificate on macOS
func uninstallCACertMacOS(certPath string) error {
	// Load certificate to get its subject
	cert, err := LoadCertificateFromFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	
	cmd := exec.Command("security", "delete-certificate", "-c", cert.Subject.CommonName, "/Library/Keychains/System.keychain")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to uninstall CA certificate: %w", err)
	}
	
	return nil
}

// installCACertLinux installs CA certificate on Linux
func installCACertLinux(certPath string) error {
	// Copy to system CA directory
	caDir := "/usr/local/share/ca-certificates"
	if err := os.MkdirAll(caDir, 0755); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}
	
	basename := filepath.Base(certPath)
	if !strings.HasSuffix(basename, ".crt") {
		basename += ".crt"
	}
	
	destPath := filepath.Join(caDir, basename)
	
	// Copy certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}
	
	if err := os.WriteFile(destPath, certData, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	
	// Update CA certificates
	cmd := exec.Command("update-ca-certificates")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update CA certificates: %w", err)
	}
	
	return nil
}

// uninstallCACertLinux removes CA certificate on Linux
func uninstallCACertLinux(certPath string) error {
	basename := filepath.Base(certPath)
	if !strings.HasSuffix(basename, ".crt") {
		basename += ".crt"
	}
	
	destPath := filepath.Join("/usr/local/share/ca-certificates", basename)
	
	// Remove certificate file
	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove certificate: %w", err)
	}
	
	// Update CA certificates
	cmd := exec.Command("update-ca-certificates")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update CA certificates: %w", err)
	}
	
	return nil
}