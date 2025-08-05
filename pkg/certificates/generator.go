package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// CertificateGenerator handles dynamic certificate generation
type CertificateGenerator struct {
	caManager   *CAManager
	keySize     int
	validDays   int
	serialCount int64
}

// NewCertificateGenerator creates a new certificate generator
func NewCertificateGenerator(caManager *CAManager) *CertificateGenerator {
	return &CertificateGenerator{
		caManager:   caManager,
		keySize:     2048,
		validDays:   365,
		serialCount: 2, // Start from 2 since CA uses 1
	}
}

// GenerateCertificate creates a new certificate for the given domain(s)
func (cg *CertificateGenerator) GenerateCertificate(domains []string) (*GeneratedCertificate, error) {
	if !cg.caManager.IsCALoaded() {
		return nil, fmt.Errorf("CA certificate not loaded")
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain must be specified")
	}

	// Generate private key for the certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, cg.keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(cg.nextSerial()),
		Subject: pkix.Name{
			Organization:  []string{"Breakthru Proxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    domains[0], // Use first domain as CN
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, cg.validDays),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         false,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
	}

	// Add Subject Alternative Names (SAN)
	for _, domain := range domains {
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, domain)
		}
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		cg.caManager.GetCACertificate(),
		&privateKey.PublicKey,
		cg.caManager.GetCAPrivateKey(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return &GeneratedCertificate{
		Certificate: cert,
		PrivateKey:  privateKey,
		Domains:     domains,
		GeneratedAt: time.Now(),
	}, nil
}

// GenerateCertificateForHost creates a certificate for a single host
func (cg *CertificateGenerator) GenerateCertificateForHost(host string) (*GeneratedCertificate, error) {
	// Clean the host (remove port if present)
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	return cg.GenerateCertificate([]string{host})
}

// GenerateWildcardCertificate creates a wildcard certificate for a domain
func (cg *CertificateGenerator) GenerateWildcardCertificate(domain string) (*GeneratedCertificate, error) {
	wildcardDomain := "*." + domain
	return cg.GenerateCertificate([]string{wildcardDomain, domain})
}

// nextSerial returns the next serial number for certificate generation
func (cg *CertificateGenerator) nextSerial() int64 {
	cg.serialCount++
	return cg.serialCount
}

// SetValidityPeriod sets the validity period for generated certificates
func (cg *CertificateGenerator) SetValidityPeriod(days int) {
	if days > 0 {
		cg.validDays = days
	}
}

// SetKeySize sets the key size for generated certificates
func (cg *CertificateGenerator) SetKeySize(size int) error {
	if size < 1024 {
		return fmt.Errorf("key size must be at least 1024 bits")
	}
	cg.keySize = size
	return nil
}

// GeneratedCertificate holds a generated certificate and its private key
type GeneratedCertificate struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	Domains     []string
	GeneratedAt time.Time
}

// ToPEM converts the certificate and key to PEM format
func (gc *GeneratedCertificate) ToPEM() (certPEM, keyPEM []byte, err error) {
	// Convert certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: gc.Certificate.Raw,
	})

	// Convert private key to PEM
	keyBytes := x509.MarshalPKCS1PrivateKey(gc.PrivateKey)
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	return certPEM, keyPEM, nil
}

// IsValidForHost checks if the certificate is valid for the given host
func (gc *GeneratedCertificate) IsValidForHost(host string) bool {
	// Clean the host (remove port if present)
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	// Check DNS names
	for _, dnsName := range gc.Certificate.DNSNames {
		if matchesDNSName(dnsName, host) {
			return true
		}
	}

	// Check IP addresses
	if ip := net.ParseIP(host); ip != nil {
		for _, certIP := range gc.Certificate.IPAddresses {
			if ip.Equal(certIP) {
				return true
			}
		}
	}

	return false
}

// IsExpired checks if the certificate has expired
func (gc *GeneratedCertificate) IsExpired() bool {
	return time.Now().After(gc.Certificate.NotAfter)
}

// ExpiresWithin checks if the certificate expires within the given duration
func (gc *GeneratedCertificate) ExpiresWithin(duration time.Duration) bool {
	return time.Now().Add(duration).After(gc.Certificate.NotAfter)
}

// GetInfo returns certificate information
func (gc *GeneratedCertificate) GetInfo() *CertificateInfo {
	return &CertificateInfo{
		Subject:    gc.Certificate.Subject.String(),
		Issuer:     gc.Certificate.Issuer.String(),
		NotBefore:  gc.Certificate.NotBefore,
		NotAfter:   gc.Certificate.NotAfter,
		IsCA:       gc.Certificate.IsCA,
		KeyUsage:   gc.Certificate.KeyUsage,
		CommonName: gc.Certificate.Subject.CommonName,
	}
}

// matchesDNSName checks if a DNS name matches a host (supports wildcards)
func matchesDNSName(dnsName, host string) bool {
	// Exact match
	if dnsName == host {
		return true
	}

	// Wildcard match
	if strings.HasPrefix(dnsName, "*.") {
		domain := dnsName[2:] // Remove "*."
		
		// Also match the domain itself (*.example.com matches example.com)
		if host == domain {
			return true
		}
		
		// Check if host ends with the domain and has exactly one more label
		if strings.HasSuffix(host, "."+domain) {
			// Ensure only one additional level (no sub.sub.example.com for *.example.com)
			prefix := host[:len(host)-len(domain)-1] // Remove ".domain" part
			if !strings.Contains(prefix, ".") {
				return true
			}
		}
	}

	return false
}