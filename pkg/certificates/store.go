package certificates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertificateStore manages certificate storage and caching
type CertificateStore struct {
	storePath string
	cache     map[string]*GeneratedCertificate
	cacheMu   sync.RWMutex
	generator *CertificateGenerator
}

// NewCertificateStore creates a new certificate store
func NewCertificateStore(storePath string, generator *CertificateGenerator) *CertificateStore {
	return &CertificateStore{
		storePath: storePath,
		cache:     make(map[string]*GeneratedCertificate),
		generator: generator,
	}
}

// GetCertificate returns a certificate for the given host
// If not found in cache, generates a new one
func (cs *CertificateStore) GetCertificate(host string) (*GeneratedCertificate, error) {
	// Clean the host (remove port if present)
	cleanHost := cs.cleanHost(host)
	
	cs.cacheMu.RLock()
	cert, exists := cs.cache[cleanHost]
	cs.cacheMu.RUnlock()
	
	// Check if cached certificate is valid and not expired
	if exists && !cert.IsExpired() && cert.IsValidForHost(cleanHost) {
		return cert, nil
	}
	
	// Try to load from disk
	if diskCert, err := cs.loadFromDisk(cleanHost); err == nil {
		if !diskCert.IsExpired() && diskCert.IsValidForHost(cleanHost) {
			cs.cacheMu.Lock()
			cs.cache[cleanHost] = diskCert
			cs.cacheMu.Unlock()
			return diskCert, nil
		}
	}
	
	// Generate new certificate
	newCert, err := cs.generator.GenerateCertificateForHost(cleanHost)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %w", cleanHost, err)
	}
	
	// Cache the certificate
	cs.cacheMu.Lock()
	cs.cache[cleanHost] = newCert
	cs.cacheMu.Unlock()
	
	// Save to disk
	if err := cs.saveToDisk(cleanHost, newCert); err != nil {
		// Log error but don't fail - certificate is still usable
		fmt.Printf("Warning: failed to save certificate to disk: %v\n", err)
	}
	
	return newCert, nil
}

// GetWildcardCertificate returns a wildcard certificate for the given domain
func (cs *CertificateStore) GetWildcardCertificate(domain string) (*GeneratedCertificate, error) {
	wildcardKey := "*." + domain
	
	cs.cacheMu.RLock()
	cert, exists := cs.cache[wildcardKey]
	cs.cacheMu.RUnlock()
	
	// Check if cached certificate is valid and not expired
	if exists && !cert.IsExpired() {
		return cert, nil
	}
	
	// Try to load from disk
	if diskCert, err := cs.loadFromDisk(wildcardKey); err == nil {
		if !diskCert.IsExpired() {
			cs.cacheMu.Lock()
			cs.cache[wildcardKey] = diskCert
			cs.cacheMu.Unlock()
			return diskCert, nil
		}
	}
	
	// Generate new wildcard certificate
	newCert, err := cs.generator.GenerateWildcardCertificate(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wildcard certificate for %s: %w", domain, err)
	}
	
	// Cache the certificate
	cs.cacheMu.Lock()
	cs.cache[wildcardKey] = newCert
	cs.cacheMu.Unlock()
	
	// Save to disk
	if err := cs.saveToDisk(wildcardKey, newCert); err != nil {
		fmt.Printf("Warning: failed to save wildcard certificate to disk: %v\n", err)
	}
	
	return newCert, nil
}

// PreloadCertificates loads certificates from disk into cache
func (cs *CertificateStore) PreloadCertificates() error {
	if err := os.MkdirAll(cs.storePath, 0755); err != nil {
		return fmt.Errorf("failed to create certificate store directory: %w", err)
	}
	
	entries, err := os.ReadDir(cs.storePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate store directory: %w", err)
	}
	
	cs.cacheMu.Lock()
	defer cs.cacheMu.Unlock()
	
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		
		host := strings.TrimSuffix(entry.Name(), ".crt")
		cert, err := cs.loadFromDiskLocked(host)
		if err != nil {
			fmt.Printf("Warning: failed to load certificate for %s: %v\n", host, err)
			continue
		}
		
		// Only cache if not expired
		if !cert.IsExpired() {
			cs.cache[host] = cert
		} else {
			// Remove expired certificate from disk
			cs.removeFromDisk(host)
		}
	}
	
	return nil
}

// CleanupExpired removes expired certificates from cache and disk
func (cs *CertificateStore) CleanupExpired() error {
	cs.cacheMu.Lock()
	defer cs.cacheMu.Unlock()
	
	var expiredHosts []string
	
	// Find expired certificates in cache
	for host, cert := range cs.cache {
		if cert.IsExpired() {
			expiredHosts = append(expiredHosts, host)
		}
	}
	
	// Remove from cache and disk
	for _, host := range expiredHosts {
		delete(cs.cache, host)
		if err := cs.removeFromDisk(host); err != nil {
			fmt.Printf("Warning: failed to remove expired certificate file for %s: %v\n", host, err)
		}
	}
	
	return nil
}

// GetCacheStats returns statistics about the certificate cache
func (cs *CertificateStore) GetCacheStats() CacheStats {
	cs.cacheMu.RLock()
	defer cs.cacheMu.RUnlock()
	
	stats := CacheStats{
		TotalCertificates: len(cs.cache),
	}
	
	for _, cert := range cs.cache {
		if cert.IsExpired() {
			stats.ExpiredCertificates++
		} else if cert.ExpiresWithin(24 * time.Hour) {
			stats.ExpiringSoon++
		}
	}
	
	return stats
}

// ListCertificates returns information about all cached certificates
func (cs *CertificateStore) ListCertificates() []CertificateEntry {
	cs.cacheMu.RLock()
	defer cs.cacheMu.RUnlock()
	
	var entries []CertificateEntry
	
	for host, cert := range cs.cache {
		entries = append(entries, CertificateEntry{
			Host:        host,
			Domains:     cert.Domains,
			NotBefore:   cert.Certificate.NotBefore,
			NotAfter:    cert.Certificate.NotAfter,
			IsExpired:   cert.IsExpired(),
			GeneratedAt: cert.GeneratedAt,
		})
	}
	
	return entries
}

// loadFromDisk loads a certificate from disk (with lock)
func (cs *CertificateStore) loadFromDisk(host string) (*GeneratedCertificate, error) {
	cs.cacheMu.RLock()
	defer cs.cacheMu.RUnlock()
	return cs.loadFromDiskLocked(host)
}

// loadFromDiskLocked loads a certificate from disk without acquiring lock
func (cs *CertificateStore) loadFromDiskLocked(host string) (*GeneratedCertificate, error) {
	certPath := filepath.Join(cs.storePath, cs.filenameSafe(host)+".crt")
	keyPath := filepath.Join(cs.storePath, cs.filenameSafe(host)+".key")
	
	// Load certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	
	// Load private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	
	return cs.parseCertificateAndKey(certData, keyData, host)
}

// saveToDisk saves a certificate to disk
func (cs *CertificateStore) saveToDisk(host string, cert *GeneratedCertificate) error {
	if err := os.MkdirAll(cs.storePath, 0755); err != nil {
		return fmt.Errorf("failed to create certificate store directory: %w", err)
	}
	
	certPEM, keyPEM, err := cert.ToPEM()
	if err != nil {
		return fmt.Errorf("failed to convert certificate to PEM: %w", err)
	}
	
	safeHost := cs.filenameSafe(host)
	certPath := filepath.Join(cs.storePath, safeHost+".crt")
	keyPath := filepath.Join(cs.storePath, safeHost+".key")
	
	// Save certificate
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}
	
	// Save private key with restricted permissions
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}
	
	return nil
}

// removeFromDisk removes certificate files from disk
func (cs *CertificateStore) removeFromDisk(host string) error {
	safeHost := cs.filenameSafe(host)
	certPath := filepath.Join(cs.storePath, safeHost+".crt")
	keyPath := filepath.Join(cs.storePath, safeHost+".key")
	
	// Remove certificate file (ignore error if doesn't exist)
	os.Remove(certPath)
	
	// Remove key file (ignore error if doesn't exist)
	os.Remove(keyPath)
	
	return nil
}

// parseCertificateAndKey parses PEM-encoded certificate and key data
func (cs *CertificateStore) parseCertificateAndKey(certData, keyData []byte, host string) (*GeneratedCertificate, error) {
	cert, key, err := ParseCertificateAndKey(certData, keyData)
	if err != nil {
		return nil, err
	}
	
	// Determine domains from certificate
	domains := cert.DNSNames
	for _, ip := range cert.IPAddresses {
		domains = append(domains, ip.String())
	}
	
	return &GeneratedCertificate{
		Certificate: cert,
		PrivateKey:  key,
		Domains:     domains,
		GeneratedAt: cert.NotBefore, // Use certificate creation time
	}, nil
}

// cleanHost removes port from host if present
func (cs *CertificateStore) cleanHost(host string) string {
	if strings.Contains(host, ":") {
		return strings.Split(host, ":")[0]
	}
	return host
}

// filenameSafe converts a hostname to a safe filename
func (cs *CertificateStore) filenameSafe(host string) string {
	// Replace unsafe characters with underscores
	safe := strings.ReplaceAll(host, "*", "wildcard")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, ":", "_")
	safe = strings.ReplaceAll(safe, "?", "_")
	safe = strings.ReplaceAll(safe, "<", "_")
	safe = strings.ReplaceAll(safe, ">", "_")
	safe = strings.ReplaceAll(safe, "|", "_")
	return safe
}

// CacheStats holds certificate cache statistics
type CacheStats struct {
	TotalCertificates   int
	ExpiredCertificates int
	ExpiringSoon        int
}

// CertificateEntry holds information about a certificate in the store
type CertificateEntry struct {
	Host        string
	Domains     []string
	NotBefore   time.Time
	NotAfter    time.Time
	IsExpired   bool
	GeneratedAt time.Time
}