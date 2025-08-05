package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TLSInfo holds information extracted from TLS handshake
type TLSInfo struct {
	ServerName string   // SNI (Server Name Indication)
	Version    uint16   // TLS version
	CipherSuites []uint16 // Supported cipher suites
}

// extractTLSInfo attempts to extract TLS information from the initial handshake data
// This is used for transparent interception to get SNI without terminating the connection
func extractTLSInfo(data []byte) (*TLSInfo, error) {
	if len(data) < 43 {
		return nil, fmt.Errorf("data too short for TLS handshake")
	}

	// Check if this is a TLS handshake record
	if data[0] != 0x16 { // TLS Handshake record type
		return nil, fmt.Errorf("not a TLS handshake record")
	}

	// Check TLS version in record header
	tlsVersion := uint16(data[1])<<8 | uint16(data[2])
	if tlsVersion < 0x0301 { // TLS 1.0 minimum
		return nil, fmt.Errorf("unsupported TLS version: %04x", tlsVersion)
	}

	// Skip record header (5 bytes) and handshake header (4 bytes)
	offset := 9
	if len(data) < offset+2+32+1 { // client version (2) + client random (32) + session ID length (1)
		return nil, fmt.Errorf("insufficient data for ClientHello")
	}

	info := &TLSInfo{
		Version: tlsVersion,
	}

	// Skip client version (2 bytes) and client random (32 bytes)
	offset += 2 + 32

	// Skip session ID
	if len(data) < offset+1 {
		return nil, fmt.Errorf("insufficient data for session ID length")
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites
	if len(data) < offset+2 {
		return nil, fmt.Errorf("insufficient data for cipher suites length")
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	// Skip compression methods
	if len(data) < offset+1 {
		return nil, fmt.Errorf("insufficient data for compression methods length")
	}
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	// Parse extensions
	if len(data) < offset+2 {
		return nil, fmt.Errorf("insufficient data for extensions length")
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if len(data) < offset+extensionsLen {
		return nil, fmt.Errorf("insufficient data for extensions")
	}

	// Parse extensions to find SNI
	extensionsEnd := offset + extensionsLen
	for offset < extensionsEnd {
		if len(data) < offset+4 {
			break
		}

		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if len(data) < offset+extLen {
			break
		}

		if extType == 0x0000 { // SNI extension
			sni, err := parseSNIExtension(data[offset : offset+extLen])
			if err == nil {
				info.ServerName = sni
			}
		}

		offset += extLen
	}

	return info, nil
}

// parseSNIExtension parses the Server Name Indication extension
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 5 {
		return "", fmt.Errorf("SNI extension too short")
	}

	// Skip server name list length (2 bytes)
	offset := 2

	// Parse server name entries
	for offset < len(data) {
		if len(data) < offset+3 {
			return "", fmt.Errorf("insufficient data for server name entry")
		}

		nameType := data[offset]
		nameLen := int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if len(data) < offset+nameLen {
			return "", fmt.Errorf("insufficient data for server name")
		}

		if nameType == 0x00 { // host_name type
			return string(data[offset : offset+nameLen]), nil
		}

		offset += nameLen
	}

	return "", fmt.Errorf("no hostname found in SNI extension")
}

// peekTLSServerName attempts to extract the SNI from a connection without consuming the data
func peekTLSServerName(conn net.Conn) (string, error) {
	// Set a short read timeout for peeking
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer tcpConn.SetReadDeadline(time.Time{}) // Reset deadline
	}

	// Read enough data for TLS handshake (typically first 512 bytes is sufficient)
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to read TLS handshake: %w", err)
	}

	// Extract TLS info from the handshake
	tlsInfo, err := extractTLSInfo(buffer[:n])
	if err != nil {
		return "", fmt.Errorf("failed to extract TLS info: %w", err)
	}

	return tlsInfo.ServerName, nil
}

// createTLSConfigForHost creates a TLS configuration for intercepting a specific host
func (s *Server) createTLSConfigForHost(hostname string) (*tls.Config, error) {
	// Get or generate certificate for the hostname
	cert, err := s.certStore.GetCertificate(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate for %s: %w", hostname, err)
	}

	// Convert to TLS certificate
	certPEM, keyPEM, err := cert.ToPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to convert certificate to PEM: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ServerName:   hostname,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		// Allow insecure ciphers for compatibility with older clients
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}, nil
}

// createClientTLSConfig creates a TLS configuration for connecting to the target server
func (s *Server) createClientTLSConfig(hostname string) *tls.Config {
	return &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: s.config.HTTPSSkipVerify, // Use config setting for certificate verification
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
}

// isTLSHandshake checks if the given data looks like a TLS handshake
func isTLSHandshake(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// Check for TLS handshake record type (0x16) and version
	return data[0] == 0x16 && data[1] >= 0x03 && data[2] >= 0x01
}