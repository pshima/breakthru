package proxy

import (
	"context"
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
)

// Server represents the proxy server
type Server struct {
	config   *config.Config
	logger   logger.Logger
	listener net.Listener
	server   *http.Server
	mu       sync.RWMutex
	sessions map[string]*Session
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

		// Handle regular HTTP requests
		s.handleHTTP(w, r)
	})
}

// handleConnect handles CONNECT requests for HTTPS tunneling
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("CONNECT request", "host", r.Host, "remote", r.RemoteAddr)

	// TODO: Implement HTTPS interception and certificate generation
	http.Error(w, "CONNECT not yet implemented", http.StatusNotImplemented)
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

	// Create new request to target
	proxyReq, err := s.createProxyRequest(r, targetURL, requestBody)
	if err != nil {
		s.logger.Error("Failed to create proxy request", "error", err, "code", "008")
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - let the client handle them
			return http.ErrUseLastResponse
		},
	}

	// Execute the request
	resp, err := client.Do(proxyReq)
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

	for name, values := range src {
		// Skip hop-by-hop headers
		if hopByHopHeaders[name] {
			continue
		}

		// Copy the header
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}