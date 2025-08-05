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
	"github.com/pshima/breakthru/pkg/intercept"
)

// TransparentProxy handles intercepted traffic in transparent mode
type TransparentProxy struct {
	config      *config.Config
	logger      logger.Logger
	interceptor intercept.Interceptor
	server      *Server
	running     bool
	mu          sync.RWMutex
}

// NewTransparentProxy creates a new transparent proxy instance
func NewTransparentProxy(cfg *config.Config, log logger.Logger, server *Server) (*TransparentProxy, error) {
	// Create interceptor configuration
	interceptConfig := intercept.Config{
		Mode:         intercept.ModeTransparent,
		ProxyPort:    cfg.Port,
		IncludePorts: cfg.InterceptPorts,
		ExcludePorts: cfg.ExcludePorts,
	}
	
	interceptor, err := intercept.New(interceptConfig, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create traffic interceptor: %w", err)
	}
	
	return &TransparentProxy{
		config:      cfg,
		logger:      log,
		interceptor: interceptor,
		server:      server,
	}, nil
}

// Start begins transparent proxy operation
func (tp *TransparentProxy) Start(ctx context.Context) error {
	tp.mu.Lock()
	if tp.running {
		tp.mu.Unlock()
		return fmt.Errorf("transparent proxy already running")
	}
	tp.running = true
	tp.mu.Unlock()
	
	tp.logger.Info("Starting transparent proxy mode")
	
	// Check if we have required privileges
	if intercept.RequiresPrivileges() {
		tp.logger.Warn("Transparent mode requires elevated privileges (root/administrator)")
	}
	
	// Start the traffic interceptor
	if err := tp.interceptor.Start(ctx); err != nil {
		tp.mu.Lock()
		tp.running = false
		tp.mu.Unlock()
		return fmt.Errorf("failed to start traffic interceptor: %w", err)
	}
	
	// Start processing intercepted connections
	go tp.processInterceptedTraffic(ctx)
	
	// Start statistics reporting
	go tp.reportStats(ctx)
	
	tp.logger.Info("Transparent proxy started successfully")
	return nil
}

// Stop stops the transparent proxy
func (tp *TransparentProxy) Stop() error {
	tp.mu.Lock()
	if !tp.running {
		tp.mu.Unlock()
		return fmt.Errorf("transparent proxy not running")
	}
	tp.running = false
	tp.mu.Unlock()
	
	tp.logger.Info("Stopping transparent proxy")
	
	if err := tp.interceptor.Stop(); err != nil {
		tp.logger.Error("Error stopping interceptor", "error", err)
		return err
	}
	
	tp.logger.Info("Transparent proxy stopped")
	return nil
}

// IsRunning returns true if the transparent proxy is running
func (tp *TransparentProxy) IsRunning() bool {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.running
}

// processInterceptedTraffic processes connections intercepted by the OS-level interceptor
func (tp *TransparentProxy) processInterceptedTraffic(ctx context.Context) {
	connections := tp.interceptor.GetConnections()
	
	for {
		select {
		case <-ctx.Done():
			return
		case conn, ok := <-connections:
			if !ok {
				tp.logger.Debug("Intercepted connections channel closed")
				return
			}
			
			tp.logger.Debug("Processing intercepted connection",
				"local", conn.LocalAddr.String(),
				"remote", conn.RemoteAddr.String(),
				"protocol", conn.Protocol,
				"data_size", len(conn.Data),
			)
			
			// Handle the intercepted connection
			go tp.handleInterceptedConnection(conn)
		}
	}
}

// handleInterceptedConnection handles a single intercepted connection
func (tp *TransparentProxy) handleInterceptedConnection(conn *intercept.Connection) {
	defer func() {
		if r := recover(); r != nil {
			tp.logger.Error("Panic in intercepted connection handler", "panic", r)
		}
	}()
	
	// Check traffic type and handle appropriately
	if tp.isHTTPTraffic(conn.Data) {
		tp.handleInterceptedHTTP(conn)
	} else if tp.isTLSTraffic(conn.Data) {
		tp.handleInterceptedTLS(conn)
	} else {
		tp.handleInterceptedRaw(conn)
	}
}

// isHTTPTraffic checks if the intercepted data looks like HTTP traffic
func (tp *TransparentProxy) isHTTPTraffic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	
	// Check for HTTP methods
	httpMethods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "TRAC"}
	dataStr := string(data[:4])
	
	for _, method := range httpMethods {
		if dataStr == method {
			return true
		}
	}
	
	return false
}

// handleInterceptedHTTP handles intercepted HTTP traffic
func (tp *TransparentProxy) handleInterceptedHTTP(conn *intercept.Connection) {
	tp.logger.Debug("Handling intercepted HTTP traffic",
		"remote", conn.RemoteAddr.String(),
		"data_preview", string(conn.Data[:min(100, len(conn.Data))]),
	)
	
	// In a real implementation, this would:
	// 1. Parse the HTTP request from raw data
	// 2. Create an HTTP request object
	// 3. Process it through the normal proxy chain
	// 4. Generate an HTTP response
	// 5. Convert response back to raw packets
	// 6. Inject response using interceptor
	
	// For now, simulate processing
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
	
	if err := tp.interceptor.InjectResponse(conn, response); err != nil {
		tp.logger.Error("Failed to inject HTTP response", "error", err)
	}
}

// isTLSTraffic checks if the intercepted data looks like TLS traffic
func (tp *TransparentProxy) isTLSTraffic(data []byte) bool {
	return isTLSHandshake(data)
}

// handleInterceptedTLS handles intercepted TLS/HTTPS traffic
func (tp *TransparentProxy) handleInterceptedTLS(conn *intercept.Connection) {
	tp.logger.Debug("Handling intercepted TLS traffic",
		"remote", conn.RemoteAddr.String(),
		"local", conn.LocalAddr.String(),
		"data_size", len(conn.Data),
	)
	
	// Extract SNI from TLS handshake
	tlsInfo, err := extractTLSInfo(conn.Data)
	if err != nil {
		tp.logger.Debug("Failed to extract TLS info", "error", err)
		// Fall back to raw handling
		tp.handleInterceptedRaw(conn)
		return
	}
	
	hostname := tlsInfo.ServerName
	if hostname == "" {
		// Try to get hostname from original destination
		hostname = tp.getOriginalDestinationHost(conn)
	}
	
	tp.logger.Info("TLS connection intercepted",
		"hostname", hostname,
		"sni", tlsInfo.ServerName,
		"tls_version", fmt.Sprintf("0x%04x", tlsInfo.Version),
		"remote", conn.RemoteAddr.String(),
	)
	
	// For transparent HTTPS interception, we need to:
	// 1. Establish a raw TCP connection to handle the intercepted data
	// 2. Set up HTTPS interception using our certificate
	// 3. Forward decrypted traffic through the proxy
	
	go tp.handleTLSInterception(conn, hostname)
}

// handleTLSInterception performs transparent HTTPS interception
func (tp *TransparentProxy) handleTLSInterception(conn *intercept.Connection, hostname string) {
	tp.logger.Debug("Starting transparent TLS interception", "hostname", hostname)
	
	// Create a connection that represents the intercepted traffic
	// In a real implementation, this would create a proper net.Conn
	// that can handle the raw intercepted packets
	
	// For now, simulate the interception process
	tp.logger.Info("Transparent HTTPS interception simulated",
		"hostname", hostname,
		"intercepted_bytes", len(conn.Data),
	)
	
	// In real implementation:
	// 1. Create fake server certificate for hostname
	// 2. Perform TLS handshake with client using fake cert
	// 3. Establish separate TLS connection to real server
	// 4. Proxy decrypted HTTP traffic between client and server
	// 5. Log all decrypted requests/responses
	
	// Generate response indicating interception is active
	response := fmt.Sprintf("TLS interception active for %s", hostname)
	if err := tp.interceptor.InjectResponse(conn, []byte(response)); err != nil {
		tp.logger.Error("Failed to inject TLS interception response", "error", err, "hostname", hostname)
	}
}

// getOriginalDestinationHost extracts hostname from original destination
func (tp *TransparentProxy) getOriginalDestinationHost(conn *intercept.Connection) string {
	// Extract hostname from local address (original destination)
	host, _, err := net.SplitHostPort(conn.LocalAddr.String())
	if err != nil {
		return conn.LocalAddr.String()
	}
	return host
}

// handleInterceptedRaw handles non-HTTP/TLS intercepted traffic
func (tp *TransparentProxy) handleInterceptedRaw(conn *intercept.Connection) {
	tp.logger.Debug("Handling intercepted raw traffic",
		"remote", conn.RemoteAddr.String(),
		"protocol", conn.Protocol,
		"data_size", len(conn.Data),
	)
	
	// For non-HTTP/TLS traffic, we might:
	// 1. Log the traffic for analysis
	// 2. Apply filtering rules
	// 3. Forward to appropriate handler
	// 4. Or simply pass through unchanged
	
	// For now, just log and pass through
	tp.logger.Info("Raw traffic intercepted",
		"remote", conn.RemoteAddr.String(),
		"protocol", conn.Protocol,
		"bytes", len(conn.Data),
	)
}

// reportStats periodically reports interception statistics
func (tp *TransparentProxy) reportStats(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := tp.interceptor.GetStats()
			tp.logger.Info("Transparent proxy statistics",
				"total_connections", stats.TotalConnections,
				"active_connections", stats.ActiveConnections,
				"total_bytes_in", stats.TotalBytesIn,
				"total_bytes_out", stats.TotalBytesOut,
				"intercepted_packets", stats.InterceptedPackets,
				"dropped_packets", stats.DroppedPackets,
			)
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TransparentHTTPHandler creates an HTTP handler that works with transparent proxy mode
func (tp *TransparentProxy) TransparentHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp.logger.Debug("Transparent HTTP request",
			"method", r.Method,
			"url", r.URL.String(),
			"remote", r.RemoteAddr,
		)
		
		// Extract original destination from connection
		// In real implementation, this would use SO_ORIGINAL_DST or similar
		originalDest := tp.getOriginalDestination(r)
		if originalDest != "" {
			tp.logger.Debug("Original destination", "dest", originalDest)
			// Update request to reflect original destination
			if host, port, err := net.SplitHostPort(originalDest); err == nil {
				r.Host = host
				if port != "80" && port != "443" {
					r.Host += ":" + port
				}
			}
		}
		
		// Process through normal proxy handler
		tp.server.handleHTTP(w, r)
	})
}

// getOriginalDestination extracts the original destination from a transparently redirected connection
func (tp *TransparentProxy) getOriginalDestination(r *http.Request) string {
	// In real implementation, this would:
	// 1. Use SO_ORIGINAL_DST socket option (Linux)
	// 2. Use pfctl state lookup (macOS)
	// 3. Use WinDivert packet info (Windows)
	
	// For simulation, return a placeholder
	return "example.com:80"
}