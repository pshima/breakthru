package certificates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

// CertificateCLI provides command-line interface for certificate management
type CertificateCLI struct {
	caManager *CAManager
	store     *CertificateStore
	generator *CertificateGenerator
}

// NewCertificateCLI creates a new certificate CLI instance
func NewCertificateCLI(caManager *CAManager, store *CertificateStore, generator *CertificateGenerator) *CertificateCLI {
	return &CertificateCLI{
		caManager: caManager,
		store:     store,
		generator: generator,
	}
}

// GenerateCA generates a new CA certificate and key
func (cli *CertificateCLI) GenerateCA(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("both certificate and key paths must be specified")
	}

	// Check if files already exist
	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("CA certificate file already exists: %s", certPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("CA key file already exists: %s", keyPath)
	}

	// Create CA manager with specified paths
	caManager := NewCAManager(certPath, keyPath)

	// Generate CA
	if err := caManager.GenerateCA(); err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	fmt.Printf("✓ CA certificate generated successfully\n")
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private Key: %s\n", keyPath)
	fmt.Printf("\nTo install the CA certificate in your system trust store, run:\n")
	fmt.Printf("  breakthru --install-ca %s\n", certPath)

	return nil
}

// ShowCertificateInfo displays information about a certificate file
func (cli *CertificateCLI) ShowCertificateInfo(certPath string) error {
	cert, err := LoadCertificateFromFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	info := &CertificateInfo{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		IsCA:       cert.IsCA,
		KeyUsage:   cert.KeyUsage,
		CommonName: cert.Subject.CommonName,
	}

	fmt.Printf("Certificate Information for: %s\n", certPath)
	fmt.Printf("=" + strings.Repeat("=", len(certPath)+28) + "\n\n")
	fmt.Print(FormatCertificateInfo(info))

	// Show DNS names and IP addresses
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names: %v\n", cert.DNSNames)
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
	}

	// Show fingerprint
	fingerprint := GetCertificateFingerprint(cert)
	fmt.Printf("Fingerprint (SHA-256): %s\n", fingerprint[:64]+"...")

	return nil
}

// InstallCA installs the CA certificate in the system trust store
func (cli *CertificateCLI) InstallCA(certPath string) error {
	// Verify certificate exists and is valid CA
	cert, err := LoadCertificateFromFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	if !cert.IsCA {
		return fmt.Errorf("certificate is not a CA certificate")
	}

	// Check if certificate is expired
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("CA certificate has expired")
	}

	fmt.Printf("Installing CA certificate: %s\n", cert.Subject.CommonName)
	fmt.Printf("This operation may require administrator privileges.\n\n")

	if err := InstallCACertificate(certPath); err != nil {
		return fmt.Errorf("failed to install CA certificate: %w", err)
	}

	fmt.Printf("✓ CA certificate installed successfully\n")
	fmt.Printf("  Applications should now trust certificates signed by this CA\n")
	fmt.Printf("  Common Name: %s\n", cert.Subject.CommonName)

	return nil
}

// UninstallCA removes the CA certificate from the system trust store
func (cli *CertificateCLI) UninstallCA(certPath string) error {
	// Verify certificate exists
	cert, err := LoadCertificateFromFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	fmt.Printf("Uninstalling CA certificate: %s\n", cert.Subject.CommonName)
	fmt.Printf("This operation may require administrator privileges.\n\n")

	if err := UninstallCACertificate(certPath); err != nil {
		return fmt.Errorf("failed to uninstall CA certificate: %w", err)
	}

	fmt.Printf("✓ CA certificate uninstalled successfully\n")

	return nil
}

// ListCertificates lists all certificates in the store
func (cli *CertificateCLI) ListCertificates() error {
	if cli.store == nil {
		return fmt.Errorf("certificate store not initialized")
	}

	entries := cli.store.ListCertificates()
	if len(entries) == 0 {
		fmt.Println("No certificates found in store")
		return nil
	}

	fmt.Printf("Certificate Store Contents (%d certificates)\n", len(entries))
	fmt.Printf("=" + strings.Repeat("=", 40) + "\n\n")

	// Create tabwriter for aligned output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tDOMAINS\tSTATUS\tEXPIRES\tGENERATED")
	fmt.Fprintln(w, "----\t-------\t------\t-------\t---------")

	for _, entry := range entries {
		status := "Valid"
		if entry.IsExpired {
			status = "EXPIRED"
		} else if time.Until(entry.NotAfter) < 7*24*time.Hour {
			status = "Expiring Soon"
		}

		domains := entry.Host
		if len(entry.Domains) > 1 {
			domains = fmt.Sprintf("%s (+%d)", entry.Host, len(entry.Domains)-1)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			entry.Host,
			domains,
			status,
			entry.NotAfter.Format("2006-01-02"),
			entry.GeneratedAt.Format("2006-01-02"),
		)
	}

	w.Flush()

	// Show statistics
	stats := cli.store.GetCacheStats()
	fmt.Printf("\nStatistics:\n")
	fmt.Printf("  Total: %d\n", stats.TotalCertificates)
	fmt.Printf("  Expired: %d\n", stats.ExpiredCertificates)
	fmt.Printf("  Expiring Soon: %d\n", stats.ExpiringSoon)

	return nil
}

// CleanupCertificates removes expired certificates from the store
func (cli *CertificateCLI) CleanupCertificates() error {
	if cli.store == nil {
		return fmt.Errorf("certificate store not initialized")
	}

	fmt.Printf("Cleaning up expired certificates...\n")

	if err := cli.store.CleanupExpired(); err != nil {
		return fmt.Errorf("failed to cleanup certificates: %w", err)
	}

	stats := cli.store.GetCacheStats()
	fmt.Printf("✓ Cleanup completed\n")
	fmt.Printf("  Remaining certificates: %d\n", stats.TotalCertificates)

	return nil
}

// GenerateCertificate generates a certificate for specified domains
func (cli *CertificateCLI) GenerateCertificate(domains []string, outputDir string) error {
	if len(domains) == 0 {
		return fmt.Errorf("at least one domain must be specified")
	}

	if cli.generator == nil {
		return fmt.Errorf("certificate generator not initialized")
	}

	cert, err := cli.generator.GenerateCertificate(domains)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Save certificate and key to files
	if outputDir == "" {
		outputDir = "."
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Use first domain as filename
	baseName := domains[0]
	if baseName == "*" || strings.HasPrefix(baseName, "*.") {
		baseName = strings.ReplaceAll(baseName, "*", "wildcard")
	}

	certPath := filepath.Join(outputDir, baseName+".crt")
	keyPath := filepath.Join(outputDir, baseName+".key")

	certPEM, keyPEM, err := cert.ToPEM()
	if err != nil {
		return fmt.Errorf("failed to convert certificate to PEM: %w", err)
	}

	// Write certificate
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Write private key with restricted permissions
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	fmt.Printf("✓ Certificate generated successfully\n")
	fmt.Printf("  Domains: %v\n", domains)
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private Key: %s\n", keyPath)
	fmt.Printf("  Valid Until: %s\n", cert.Certificate.NotAfter.Format(time.RFC3339))

	return nil
}

// ValidateCertificate validates a certificate file
func (cli *CertificateCLI) ValidateCertificate(certPath string, host string) error {
	cert, err := LoadCertificateFromFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	fmt.Printf("Validating certificate: %s\n", certPath)

	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		fmt.Printf("❌ Certificate is not yet valid (valid from: %s)\n", cert.NotBefore.Format(time.RFC3339))
		return fmt.Errorf("certificate not yet valid")
	}

	if now.After(cert.NotAfter) {
		fmt.Printf("❌ Certificate has expired (expired: %s)\n", cert.NotAfter.Format(time.RFC3339))
		return fmt.Errorf("certificate expired")
	}

	fmt.Printf("✓ Certificate is not expired\n")

	// Check host if specified
	if host != "" {
		if IsCertificateValidForHost(cert, host) {
			fmt.Printf("✓ Certificate is valid for host: %s\n", host)
		} else {
			fmt.Printf("❌ Certificate is NOT valid for host: %s\n", host)
			fmt.Printf("  Certificate DNS names: %v\n", cert.DNSNames)
			if len(cert.IPAddresses) > 0 {
				fmt.Printf("  Certificate IP addresses: %v\n", cert.IPAddresses)
			}
			return fmt.Errorf("certificate not valid for host")
		}
	}

	// Show basic info
	fmt.Printf("✓ Certificate is valid\n")
	fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("  Valid until: %s\n", cert.NotAfter.Format(time.RFC3339))
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
	fmt.Printf("  Days remaining: %d\n", daysRemaining)

	return nil
}