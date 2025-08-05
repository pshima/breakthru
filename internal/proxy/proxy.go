package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
	s.logger.Info("HTTP request", 
		"method", r.Method,
		"url", r.URL.String(),
		"host", r.Host,
		"remote", r.RemoteAddr,
	)

	// Log request headers
	s.logHeaders("Request", r.Header)

	// TODO: Implement HTTP request forwarding and response handling
	http.Error(w, "HTTP proxy not yet implemented", http.StatusNotImplemented)
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