package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pshima/breakthru/internal/config"
	"github.com/pshima/breakthru/internal/logger"
	"github.com/pshima/breakthru/pkg/certificates"
)

// Server represents the proxy server
type Server struct {
	config          *config.Config
	logger          logger.Logger
	listener        net.Listener
	server          *http.Server
	mu              sync.RWMutex
	sessions        map[string]*Session
	client          *http.Client
	transparentProxy *TransparentProxy
	
	// Certificate management components
	caManager       *certificates.CAManager
	certGenerator   *certificates.CertificateGenerator
	certStore       *certificates.CertificateStore
}

// Session represents a proxy session
type Session struct {
	ID        string
	StartTime time.Time
	ClientIP  string
}

// New creates a new proxy server instance
func New(cfg *config.Config, log logger.Logger) (*Server, error) {
	s := &Server{
		config:   cfg,
		logger:   log,
		sessions: make(map[string]*Session),
	}

	// Create HTTP client with connection pooling
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false, // Enable keep-alive
	}

	s.client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - let the client handle them
			return http.ErrUseLastResponse
		},
	}

	// Initialize certificate management components
	if err := s.initializeCertificates(cfg, log); err != nil {
		return nil, fmt.Errorf("failed to initialize certificates: %w", err)
	}

	// Initialize transparent proxy if enabled
	if cfg.TransparentMode {
		transparentProxy, err := NewTransparentProxy(cfg, log, s)
		if err != nil {
			return nil, fmt.Errorf("failed to create transparent proxy: %w", err)
		}
		s.transparentProxy = transparentProxy
		log.Info("Transparent proxy initialized")
	}

	handler := s.createHandler()
	
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

// Start starts the proxy server
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	// Start transparent proxy if enabled
	if s.transparentProxy != nil {
		if err := s.transparentProxy.Start(ctx); err != nil {
			return fmt.Errorf("failed to start transparent proxy: %w", err)
		}
	}

	// Start server in goroutine
	go func() {
		if s.config.HTTPSMode && s.config.CertFile != "" && s.config.KeyFile != "" {
			s.logger.Info("Starting HTTPS proxy server", "addr", s.server.Addr)
			err = s.server.ServeTLS(s.listener, s.config.CertFile, s.config.KeyFile)
		} else {
			s.logger.Info("Starting HTTP proxy server", "addr", s.server.Addr)
			err = s.server.Serve(s.listener)
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("Server error", "error", err, "code", "004")
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	
	s.logger.Info("Shutting down proxy server")
	
	// Stop transparent proxy if running
	if s.transparentProxy != nil && s.transparentProxy.IsRunning() {
		if err := s.transparentProxy.Stop(); err != nil {
			s.logger.Error("Error stopping transparent proxy", "error", err)
		}
	}
	
	// Close idle connections in the HTTP client
	if transport, ok := s.client.Transport.(*http.Transport); ok {
		s.logger.Debug("Closing idle connections")
		transport.CloseIdleConnections()
	}
	
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("Shutdown error", "error", err, "code", "005")
		return err
	}
	
	return nil
}

// createHandler creates the HTTP handler for the proxy
func (s *Server) createHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Debug("Incoming request", 
			"method", r.Method,
			"url", r.URL.String(),
			"remote", r.RemoteAddr,
			"host", r.Host,
		)

		// Handle CONNECT method for HTTPS tunneling
		if r.Method == http.MethodConnect {
			s.handleConnect(w, r)
			return
		}

		// Check for WebSocket upgrade request
		if s.isWebSocketUpgrade(r) {
			s.handleWebSocket(w, r)
			return
		}

		// Handle regular HTTP requests
		s.handleHTTP(w, r)
	})
}

// handleConnect handles CONNECT requests for HTTPS interception
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("CONNECT request", "host", r.Host, "remote", r.RemoteAddr)

	// Extract hostname from the CONNECT request
	hostname := r.Host
	if hostname == "" {
		s.logger.Error("Empty hostname in CONNECT request", "code", "020")
		http.Error(w, "Bad Request: Empty hostname", http.StatusBadRequest)
		return
	}

	// Remove port from hostname if present for certificate generation
	originalHost := hostname
	if colonIndex := strings.LastIndex(hostname, ":"); colonIndex != -1 {
		hostname = hostname[:colonIndex]
	}

	// Check if HTTPS interception is enabled
	if !s.config.HTTPSInterception {
		s.logger.Debug("HTTPS interception disabled, tunneling connection", "hostname", hostname)
		s.handleConnectTunnel(w, r, originalHost)
		return
	}

	// Check if this domain should be bypassed
	if s.shouldBypassHTTPS(hostname) {
		s.logger.Debug("Domain bypassed for HTTPS interception", "hostname", hostname)
		s.handleConnectTunnel(w, r, originalHost)
		return
	}

	// Check if we should only intercept specific domains
	if !s.shouldInterceptHTTPS(hostname) {
		s.logger.Debug("Domain not in intercept list", "hostname", hostname)
		s.handleConnectTunnel(w, r, originalHost)
		return
	}

	s.logger.Debug("Starting HTTPS interception", "hostname", hostname)

	// Get the underlying connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.Error("Response writer does not support hijacking", "code", "021")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error("Failed to hijack connection", "error", err, "code", "022")
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established to the client
	connectResponse := "HTTP/1.1 200 Connection established\r\n\r\n"
	if _, err := clientConn.Write([]byte(connectResponse)); err != nil {
		s.logger.Error("Failed to send CONNECT response", "error", err, "code", "023")
		return
	}

	s.logger.Debug("Sent CONNECT response, starting TLS interception")

	// Start HTTPS interception
	if err := s.interceptHTTPS(clientConn, hostname, originalHost); err != nil {
		s.logger.Error("HTTPS interception failed", "error", err, "hostname", hostname, "code", "024")
		return
	}
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func (s *Server) isWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// handleWebSocket handles WebSocket upgrade requests and proxies the connection
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("WebSocket upgrade request", 
		"url", r.URL.String(),
		"host", r.Host,
		"remote", r.RemoteAddr,
		"origin", r.Header.Get("Origin"),
		"sec_websocket_key", r.Header.Get("Sec-WebSocket-Key"),
		"sec_websocket_version", r.Header.Get("Sec-WebSocket-Version"),
		"sec_websocket_protocol", r.Header.Get("Sec-WebSocket-Protocol"),
	)

	// Build target URL for WebSocket connection
	targetURL := s.buildTargetURL(r)
	if targetURL == nil {
		s.logger.Error("Failed to build WebSocket target URL", "original_url", r.URL.String(), "code", "012")
		http.Error(w, "Invalid WebSocket request URL", http.StatusBadRequest)
		return
	}

	// Convert HTTP URL to WebSocket URL
	wsScheme := "ws"
	if targetURL.Scheme == "https" {
		wsScheme = "wss"
	}
	targetURL.Scheme = wsScheme

	s.logger.Debug("Connecting to WebSocket target", "target", targetURL.String())

	// Dial the target WebSocket server
	targetConn, err := net.Dial("tcp", targetURL.Host)
	if err != nil {
		s.logger.Error("Failed to connect to WebSocket target", "error", err, "target", targetURL.Host, "code", "013")
		http.Error(w, "Failed to connect to WebSocket target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Perform WebSocket handshake with target server
	if err := s.performWebSocketHandshake(targetConn, r, targetURL); err != nil {
		s.logger.Error("WebSocket handshake failed", "error", err, "code", "014")
		http.Error(w, "WebSocket handshake failed", http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.Error("Response writer does not support hijacking", "code", "015")
		http.Error(w, "WebSocket upgrade not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error("Failed to hijack connection", "error", err, "code", "016")
		return
	}
	defer clientConn.Close()

	// Send upgrade response to client
	upgradeResponse := "HTTP/1.1 101 Switching Protocols\r\n"
	upgradeResponse += "Upgrade: websocket\r\n"
	upgradeResponse += "Connection: Upgrade\r\n"
	
	// Generate Sec-WebSocket-Accept header
	key := r.Header.Get("Sec-WebSocket-Key")
	if key != "" {
		accept := s.generateWebSocketAccept(key)
		upgradeResponse += fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", accept)
	}
	
	// Add protocol if specified
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	if protocol != "" {
		upgradeResponse += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", protocol)
	}
	
	upgradeResponse += "\r\n"

	if _, err := clientConn.Write([]byte(upgradeResponse)); err != nil {
		s.logger.Error("Failed to send upgrade response", "error", err, "code", "017")
		return
	}

	s.logger.Info("WebSocket connection established", "target", targetURL.String())

	// Start proxying WebSocket frames between client and server
	s.proxyWebSocketConnection(clientConn, targetConn)
}

// handleHTTP handles regular HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	
	s.logger.Info("HTTP request", 
		"method", r.Method,
		"url", r.URL.String(),
		"host", r.Host,
		"remote", r.RemoteAddr,
		"user_agent", r.UserAgent(),
		"content_length", r.ContentLength,
	)

	// Log request headers in debug mode
	s.logHeaders("Request", r.Header)

	// Read request body if present
	var requestBody []byte
	if r.Body != nil {
		var err error
		requestBody, err = io.ReadAll(r.Body)
		if err != nil {
			s.logger.Error("Failed to read request body", "error", err, "code", "006")
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		r.Body.Close()
		
		// Log request body for debugging (truncated if too long)
		if len(requestBody) > 0 {
			bodyStr := string(requestBody)
			if len(bodyStr) > 1000 {
				bodyStr = bodyStr[:1000] + "... (truncated)"
			}
			s.logger.Debug("Request body", "body", bodyStr, "size", len(requestBody))
		}
	}

	// Create the target URL
	targetURL := s.buildTargetURL(r)
	if targetURL == nil {
		s.logger.Error("Failed to build target URL", "original_url", r.URL.String(), "code", "007")
		http.Error(w, "Invalid request URL", http.StatusBadRequest)
		return
	}

	s.logger.Debug("Forwarding request", "target", targetURL.String())

	// Log Connection header status for debugging keep-alive
	connectionHeader := r.Header.Get("Connection")
	if connectionHeader != "" {
		s.logger.Debug("Connection header", "value", connectionHeader)
	}

	// Create new request to target
	proxyReq, err := s.createProxyRequest(r, targetURL, requestBody)
	if err != nil {
		s.logger.Error("Failed to create proxy request", "error", err, "code", "008")
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// Execute the request using the shared client with connection pooling
	resp, err := s.client.Do(proxyReq)
	if err != nil {
		s.logger.Error("Failed to forward request", "error", err, "target", targetURL.String(), "code", "009")
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	duration := time.Since(startTime)
	s.logger.Info("HTTP response", 
		"status", resp.StatusCode,
		"status_text", resp.Status,
		"content_length", resp.ContentLength,
		"content_type", resp.Header.Get("Content-Type"),
		"duration_ms", duration.Milliseconds(),
	)

	// Log response headers in debug mode
	s.logHeaders("Response", resp.Header)

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body and log it
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", "error", err, "code", "010")
		return
	}

	// Log response body for debugging (truncated if too long)
	if len(responseBody) > 0 {
		bodyStr := string(responseBody)
		if len(bodyStr) > 1000 {
			bodyStr = bodyStr[:1000] + "... (truncated)"
		}
		s.logger.Debug("Response body", "body", bodyStr, "size", len(responseBody))
	}

	// Write response body to client
	if _, err := w.Write(responseBody); err != nil {
		s.logger.Error("Failed to write response", "error", err, "code", "011")
	}

	s.logger.Debug("Request completed", "duration_ms", duration.Milliseconds())
}

// logHeaders logs HTTP headers for debugging
func (s *Server) logHeaders(prefix string, headers http.Header) {
	for name, values := range headers {
		for _, value := range values {
			s.logger.Debug(fmt.Sprintf("%s header", prefix), "name", name, "value", value)
		}
	}
}

// GetActiveSessions returns the current active sessions
func (s *Server) GetActiveSessions() map[string]*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	sessions := make(map[string]*Session)
	for k, v := range s.sessions {
		sessions[k] = v
	}
	return sessions
}

// GetListenerAddr returns the listener address (thread-safe)
func (s *Server) GetListenerAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// buildTargetURL constructs the target URL for the proxy request
func (s *Server) buildTargetURL(r *http.Request) *url.URL {
	// For proxy requests, the URL should be absolute
	if r.URL.IsAbs() {
		return r.URL
	}

	// For non-proxy requests, construct the URL from Host header
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}

	if host == "" {
		return nil
	}

	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Fragment: r.URL.Fragment,
	}

	return targetURL
}

// createProxyRequest creates a new HTTP request to forward to the target
func (s *Server) createProxyRequest(originalReq *http.Request, targetURL *url.URL, body []byte) (*http.Request, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = strings.NewReader(string(body))
	}

	// Create new request
	req, err := http.NewRequest(originalReq.Method, targetURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %w", err)
	}

	// Copy headers, skipping hop-by-hop headers
	s.copyHeaders(req.Header, originalReq.Header)

	// Set Content-Length if we have a body
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	}

	// Remove proxy-specific headers
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	// Set Via header to indicate proxy
	via := req.Header.Get("Via")
	if via != "" {
		via += ", "
	}
	via += "1.1 breakthru"
	req.Header.Set("Via", via)

	return req, nil
}

// copyHeaders copies HTTP headers, excluding hop-by-hop headers
func (s *Server) copyHeaders(dst, src http.Header) {
	// Hop-by-hop headers as defined in RFC 2616
	hopByHopHeaders := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}

	// Check if there are any custom hop-by-hop headers in Connection header
	connectionHeaders := make(map[string]bool)
	if conn := src.Get("Connection"); conn != "" {
		for _, header := range strings.Split(conn, ",") {
			header = strings.TrimSpace(header)
			if header != "" {
				connectionHeaders[http.CanonicalHeaderKey(header)] = true
			}
		}
	}

	for name, values := range src {
		// Skip hop-by-hop headers
		if hopByHopHeaders[name] || connectionHeaders[name] {
			continue
		}

		// Copy the header
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

// performWebSocketHandshake performs the WebSocket handshake with the target server
func (s *Server) performWebSocketHandshake(conn net.Conn, originalReq *http.Request, targetURL *url.URL) error {
	// Create handshake request
	handshakeReq := fmt.Sprintf("GET %s HTTP/1.1\r\n", targetURL.RequestURI())
	handshakeReq += fmt.Sprintf("Host: %s\r\n", targetURL.Host)
	handshakeReq += "Upgrade: websocket\r\n"
	handshakeReq += "Connection: Upgrade\r\n"
	handshakeReq += fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", originalReq.Header.Get("Sec-WebSocket-Key"))
	handshakeReq += fmt.Sprintf("Sec-WebSocket-Version: %s\r\n", originalReq.Header.Get("Sec-WebSocket-Version"))
	
	// Add optional headers
	if origin := originalReq.Header.Get("Origin"); origin != "" {
		handshakeReq += fmt.Sprintf("Origin: %s\r\n", origin)
	}
	if protocol := originalReq.Header.Get("Sec-WebSocket-Protocol"); protocol != "" {
		handshakeReq += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", protocol)
	}
	if extensions := originalReq.Header.Get("Sec-WebSocket-Extensions"); extensions != "" {
		handshakeReq += fmt.Sprintf("Sec-WebSocket-Extensions: %s\r\n", extensions)
	}
	
	// Add Via header
	via := originalReq.Header.Get("Via")
	if via != "" {
		via += ", "
	}
	via += "1.1 breakthru"
	handshakeReq += fmt.Sprintf("Via: %s\r\n", via)
	
	handshakeReq += "\r\n"

	// Send handshake request
	if _, err := conn.Write([]byte(handshakeReq)); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// Read handshake response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}

	// Check for 101 Switching Protocols
	if !strings.Contains(response, "101") {
		return fmt.Errorf("unexpected handshake response: %s", strings.TrimSpace(response))
	}

	// Read and discard remaining headers until empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read handshake headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	s.logger.Debug("WebSocket handshake completed successfully")
	return nil
}

// generateWebSocketAccept generates the Sec-WebSocket-Accept header value
func (s *Server) generateWebSocketAccept(key string) string {
	const websocketMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + websocketMagicString))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// proxyWebSocketConnection handles bidirectional copying of WebSocket frames
func (s *Server) proxyWebSocketConnection(clientConn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Copy from client to target
	go func() {
		defer wg.Done()
		s.copyWebSocketFrames("client->server", clientConn, targetConn)
	}()
	
	// Copy from target to client
	go func() {
		defer wg.Done()
		s.copyWebSocketFrames("server->client", targetConn, clientConn)
	}()
	
	wg.Wait()
	s.logger.Info("WebSocket connection closed")
}

// copyWebSocketFrames copies WebSocket frames between connections with logging
func (s *Server) copyWebSocketFrames(direction string, src, dst net.Conn) {
	buffer := make([]byte, s.config.BufferSize)
	
	for {
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				s.logger.Debug("WebSocket read error", "direction", direction, "error", err)
			}
			break
		}
		
		if n > 0 {
			// Log WebSocket frame info
			s.logWebSocketFrame(direction, buffer[:n])
			
			if _, err := dst.Write(buffer[:n]); err != nil {
				s.logger.Debug("WebSocket write error", "direction", direction, "error", err)
				break
			}
		}
	}
}

// logWebSocketFrame logs WebSocket frame information
func (s *Server) logWebSocketFrame(direction string, frame []byte) {
	if len(frame) < 2 {
		return
	}
	
	// Parse WebSocket frame header
	firstByte := frame[0]
	secondByte := frame[1]
	
	fin := (firstByte & 0x80) != 0
	opcode := firstByte & 0x0F
	masked := (secondByte & 0x80) != 0
	payloadLen := int(secondByte & 0x7F)
	
	opcodeNames := map[byte]string{
		0x0: "continuation",
		0x1: "text",
		0x2: "binary",
		0x8: "close",
		0x9: "ping",
		0xA: "pong",
	}
	
	opcodeName, exists := opcodeNames[opcode]
	if !exists {
		opcodeName = fmt.Sprintf("unknown(0x%X)", opcode)
	}
	
	s.logger.Debug("WebSocket frame", 
		"direction", direction,
		"fin", fin,
		"opcode", opcodeName,
		"masked", masked,
		"payload_len", payloadLen,
		"frame_size", len(frame),
	)
	
	// For text frames, log the payload content (truncated if too long)
	if opcode == 0x1 && len(frame) > 2 {
		headerLen := 2
		if masked {
			headerLen += 4 // mask key
		}
		if payloadLen == 126 {
			headerLen += 2 // extended payload length
		} else if payloadLen == 127 {
			headerLen += 8 // extended payload length
		}
		
		if len(frame) > headerLen {
			payload := frame[headerLen:]
			if masked && len(payload) >= 4 {
				// Unmask the payload for logging
				maskKey := frame[headerLen-4 : headerLen]
				for i := range payload {
					payload[i] ^= maskKey[i%4]
				}
			}
			
			payloadStr := string(payload)
			if len(payloadStr) > 200 {
				payloadStr = payloadStr[:200] + "... (truncated)"
			}
			
			s.logger.Debug("WebSocket text message", 
				"direction", direction,
				"content", payloadStr,
			)
		}
	}
}

// initializeCertificates sets up the certificate management components
func (s *Server) initializeCertificates(cfg *config.Config, log logger.Logger) error {
	// Determine CA certificate and key paths
	caCertPath := cfg.CACert
	caKeyPath := cfg.CAKey
	
	if caCertPath == "" {
		caCertPath = cfg.CertStoreDir + "/ca.crt"
	}
	if caKeyPath == "" {
		caKeyPath = cfg.CertStoreDir + "/ca.key"
	}
	
	// Initialize CA manager
	s.caManager = certificates.NewCAManager(caCertPath, caKeyPath)
	
	// Try to load existing CA or generate new one if auto-generation is enabled
	if err := s.caManager.LoadCA(); err != nil {
		if cfg.AutoGenerateCA {
			log.Info("No CA found, generating new CA", "cert_path", caCertPath, "key_path", caKeyPath)
			if err := s.caManager.GenerateCA(); err != nil {
				return fmt.Errorf("failed to generate CA: %w", err)
			}
			log.Info("CA generated successfully", "cert_path", caCertPath)
		} else {
			return fmt.Errorf("CA certificate not found and auto-generation is disabled: %w", err)
		}
	} else {
		log.Info("CA loaded successfully", "cert_path", caCertPath)
	}
	
	// Validate the loaded CA
	if err := s.caManager.ValidateCA(); err != nil {
		return fmt.Errorf("CA validation failed: %w", err)
	}
	
	// Initialize certificate generator
	s.certGenerator = certificates.NewCertificateGenerator(s.caManager)
	s.certGenerator.SetValidityPeriod(cfg.CertValidityDays)
	if err := s.certGenerator.SetKeySize(cfg.CertKeySize); err != nil {
		return fmt.Errorf("failed to set certificate key size: %w", err)
	}
	
	// Initialize certificate store
	s.certStore = certificates.NewCertificateStore(cfg.CertStoreDir, s.certGenerator)
	
	// Preload existing certificates
	if err := s.certStore.PreloadCertificates(); err != nil {
		log.Warn("Failed to preload certificates", "error", err)
	}
	
	// Clean up expired certificates if enabled
	if cfg.CertCleanupEnabled {
		if err := s.certStore.CleanupExpired(); err != nil {
			log.Warn("Failed to cleanup expired certificates", "error", err)
		}
	}
	
	stats := s.certStore.GetCacheStats()
	log.Info("Certificate management initialized", 
		"total_certs", stats.TotalCertificates,
		"expired_certs", stats.ExpiredCertificates,
		"ca_valid_until", s.caManager.GetCACertificate().NotAfter,
	)
	
	return nil
}

// interceptHTTPS performs HTTPS man-in-the-middle interception
func (s *Server) interceptHTTPS(clientConn net.Conn, hostname, originalHost string) error {
	s.logger.Debug("Setting up TLS interception", "hostname", hostname, "original_host", originalHost)

	// Create TLS configuration for the client connection (using our generated certificate)
	serverTLSConfig, err := s.createTLSConfigForHost(hostname)
	if err != nil {
		return fmt.Errorf("failed to create server TLS config: %w", err)
	}

	// Wrap client connection with TLS server
	tlsClientConn := tls.Server(clientConn, serverTLSConfig)

	// Perform TLS handshake with client
	if err := tlsClientConn.Handshake(); err != nil {
		return fmt.Errorf("client TLS handshake failed: %w", err)
	}

	s.logger.Info("TLS handshake completed with client", 
		"hostname", hostname,
		"tls_version", tlsVersionString(tlsClientConn.ConnectionState().Version),
		"cipher_suite", tls.CipherSuiteName(tlsClientConn.ConnectionState().CipherSuite),
	)

	// Connect to the target server
	targetConn, err := net.Dial("tcp", originalHost)
	if err != nil {
		return fmt.Errorf("failed to connect to target server: %w", err)
	}
	defer targetConn.Close()

	// Create TLS client configuration for the target server connection
	clientTLSConfig := s.createClientTLSConfig(hostname)

	// Wrap target connection with TLS client
	tlsTargetConn := tls.Client(targetConn, clientTLSConfig)

	// Perform TLS handshake with target server
	if err := tlsTargetConn.Handshake(); err != nil {
		return fmt.Errorf("server TLS handshake failed: %w", err)
	}

	s.logger.Info("TLS handshake completed with server", 
		"hostname", hostname,
		"server_cert_subject", tlsTargetConn.ConnectionState().PeerCertificates[0].Subject.String(),
		"tls_version", tlsVersionString(tlsTargetConn.ConnectionState().Version),
	)

	// Start proxying HTTP traffic between client and server
	s.proxyHTTPSConnection(tlsClientConn, tlsTargetConn, hostname)

	return nil
}

// proxyHTTPSConnection handles bidirectional proxying of decrypted HTTPS traffic
func (s *Server) proxyHTTPSConnection(clientConn, serverConn *tls.Conn, hostname string) {
	s.logger.Info("Starting HTTPS traffic interception", "hostname", hostname)

	var wg sync.WaitGroup
	wg.Add(2)

	// Proxy client -> server
	go func() {
		defer wg.Done()
		defer serverConn.CloseWrite()
		s.proxyHTTPSDirection("client->server", clientConn, serverConn, hostname, true)
	}()

	// Proxy server -> client
	go func() {
		defer wg.Done()
		defer clientConn.CloseWrite()
		s.proxyHTTPSDirection("server->client", serverConn, clientConn, hostname, false)
	}()

	wg.Wait()
	s.logger.Info("HTTPS connection closed", "hostname", hostname)
}

// proxyHTTPSDirection handles HTTP traffic in one direction with full request/response logging
func (s *Server) proxyHTTPSDirection(direction string, src, dst *tls.Conn, hostname string, isRequest bool) {
	reader := bufio.NewReader(src)

	for {
		if isRequest {
			// Parse and log HTTP request
			req, err := http.ReadRequest(reader)
			if err != nil {
				if err != io.EOF {
					s.logger.Debug("Failed to read HTTP request", "error", err, "hostname", hostname)
				}
				break
			}

			// Log the intercepted HTTPS request
			s.logInterceptedRequest(req, hostname)

			// Write request to server
			if err := req.Write(dst); err != nil {
				s.logger.Error("Failed to write request to server", "error", err, "hostname", hostname, "code", "025")
				break
			}
		} else {
			// Parse and log HTTP response
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				if err != io.EOF {
					s.logger.Debug("Failed to read HTTP response", "error", err, "hostname", hostname)
				}
				break
			}

			// Log the intercepted HTTPS response
			s.logInterceptedResponse(resp, hostname)

			// Write response to client
			if err := resp.Write(dst); err != nil {
				s.logger.Error("Failed to write response to client", "error", err, "hostname", hostname, "code", "026")
				break
			}
		}
	}
}

// logInterceptedRequest logs details of an intercepted HTTPS request
func (s *Server) logInterceptedRequest(req *http.Request, hostname string) {
	startTime := time.Now()

	s.logger.Info("HTTPS request intercepted",
		"hostname", hostname,
		"method", req.Method,
		"url", req.URL.String(),
		"user_agent", req.UserAgent(),
		"content_length", req.ContentLength,
		"protocol", req.Proto,
	)

	// Log headers
	for name, values := range req.Header {
		for _, value := range values {
			s.logger.Debug("HTTPS request header", "hostname", hostname, "name", name, "value", value)
		}
	}

	// Log request body if present and enabled
	if s.config.HTTPSLogBodies && req.Body != nil && req.ContentLength > 0 {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			s.logger.Error("Failed to read request body", "error", err, "hostname", hostname, "code", "027")
		} else {
			// Replace the body so it can still be forwarded
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Respect max body size limit
			maxSize := s.config.HTTPSMaxBodySize
			bodyStr := string(bodyBytes)
			if len(bodyStr) > maxSize {
				bodyStr = bodyStr[:maxSize] + "... (truncated)"
			}
			s.logger.Info("HTTPS request body", "hostname", hostname, "body", bodyStr, "size", len(bodyBytes))
		}
	}

	s.logger.Debug("HTTPS request processing completed", "hostname", hostname, "duration_ms", time.Since(startTime).Milliseconds())
}

// logInterceptedResponse logs details of an intercepted HTTPS response
func (s *Server) logInterceptedResponse(resp *http.Response, hostname string) {
	startTime := time.Now()

	s.logger.Info("HTTPS response intercepted",
		"hostname", hostname,
		"status", resp.StatusCode,
		"status_text", resp.Status,
		"content_length", resp.ContentLength,
		"content_type", resp.Header.Get("Content-Type"),
		"protocol", resp.Proto,
	)

	// Log headers
	for name, values := range resp.Header {
		for _, value := range values {
			s.logger.Debug("HTTPS response header", "hostname", hostname, "name", name, "value", value)
		}
	}

	// Log response body if present and enabled
	if s.config.HTTPSLogBodies && resp.Body != nil && resp.ContentLength != 0 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			s.logger.Error("Failed to read response body", "error", err, "hostname", hostname, "code", "028")
		} else {
			// Replace the body so it can still be forwarded
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Respect max body size limit
			maxSize := s.config.HTTPSMaxBodySize
			bodyStr := string(bodyBytes)
			if len(bodyStr) > maxSize {
				bodyStr = bodyStr[:maxSize] + "... (truncated)"
			}
			s.logger.Info("HTTPS response body", "hostname", hostname, "body", bodyStr, "size", len(bodyBytes))
		}
	}

	s.logger.Debug("HTTPS response processing completed", "hostname", hostname, "duration_ms", time.Since(startTime).Milliseconds())
}

// tlsVersionString converts TLS version number to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// shouldBypassHTTPS checks if a domain should bypass HTTPS interception
func (s *Server) shouldBypassHTTPS(hostname string) bool {
	for _, bypassDomain := range s.config.HTTPSBypassDomains {
		if matchesDomain(bypassDomain, hostname) {
			return true
		}
	}
	return false
}

// shouldInterceptHTTPS checks if a domain should be intercepted
func (s *Server) shouldInterceptHTTPS(hostname string) bool {
	// If no only-domains specified, intercept all (except bypassed)
	if len(s.config.HTTPSOnlyDomains) == 0 {
		return true
	}
	
	// Check if hostname matches any of the only-domains
	for _, onlyDomain := range s.config.HTTPSOnlyDomains {
		if matchesDomain(onlyDomain, hostname) {
			return true
		}
	}
	return false
}

// matchesDomain checks if a hostname matches a domain pattern (supports wildcards)
func matchesDomain(pattern, hostname string) bool {
	// Exact match
	if pattern == hostname {
		return true
	}
	
	// Wildcard match
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:] // Remove "*."
		if hostname == domain {
			return true
		}
		if strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}
	
	return false
}

// handleConnectTunnel handles CONNECT requests by creating a simple tunnel (no interception)
func (s *Server) handleConnectTunnel(w http.ResponseWriter, r *http.Request, targetHost string) {
	s.logger.Debug("Creating HTTPS tunnel", "target", targetHost)
	
	// Connect to target server
	targetConn, err := net.Dial("tcp", targetHost)
	if err != nil {
		s.logger.Error("Failed to connect to target", "error", err, "target", targetHost, "code", "029")
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	
	// Get client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.Error("Response writer does not support hijacking for tunnel", "code", "030")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error("Failed to hijack connection for tunnel", "error", err, "code", "031")
		return
	}
	defer clientConn.Close()
	
	// Send connection established response
	connectResponse := "HTTP/1.1 200 Connection established\r\n\r\n"
	if _, err := clientConn.Write([]byte(connectResponse)); err != nil {
		s.logger.Error("Failed to send tunnel response", "error", err, "code", "032")
		return
	}
	
	s.logger.Info("HTTPS tunnel established", "target", targetHost)
	
	// Start bidirectional copying
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Client -> Server
	go func() {
		defer wg.Done()
		defer targetConn.Close()
		n, _ := io.Copy(targetConn, clientConn)
		s.logger.Debug("Tunnel client->server closed", "bytes", n, "target", targetHost)
	}()
	
	// Server -> Client  
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		n, _ := io.Copy(clientConn, targetConn)
		s.logger.Debug("Tunnel server->client closed", "bytes", n, "target", targetHost)
	}()
	
	wg.Wait()
	s.logger.Info("HTTPS tunnel closed", "target", targetHost)
}