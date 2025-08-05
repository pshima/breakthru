// Package intercept provides OS-level traffic interception capabilities
package intercept

import (
	"context"
	"net"

	"github.com/pshima/breakthru/internal/logger"
)

// InterceptMode defines the type of traffic interception
type InterceptMode int

const (
	// ModeDisabled - no traffic interception (default proxy mode)
	ModeDisabled InterceptMode = iota
	// ModeTransparent - transparent proxy mode with OS-level interception
	ModeTransparent
	// ModeAll - intercept all traffic (including non-HTTP)
	ModeAll
)

// Config holds configuration for traffic interception
type Config struct {
	Mode         InterceptMode `json:"mode"`
	Interface    string        `json:"interface"`     // Network interface to intercept (empty = all)
	ExcludePorts []int         `json:"exclude_ports"` // Ports to exclude from interception
	IncludePorts []int         `json:"include_ports"` // Ports to include (empty = all)
	ProxyPort    int           `json:"proxy_port"`    // Port where proxy is listening
}

// Connection represents an intercepted network connection
type Connection struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Protocol   string // "tcp" or "udp"
	Data       []byte
}

// Interceptor defines the interface for OS-level traffic interception
type Interceptor interface {
	// Start begins traffic interception
	Start(ctx context.Context) error
	
	// Stop stops traffic interception and cleans up
	Stop() error
	
	// GetConnections returns a channel of intercepted connections
	GetConnections() <-chan *Connection
	
	// InjectResponse sends a response back to the original client
	InjectResponse(conn *Connection, response []byte) error
	
	// GetStats returns interception statistics
	GetStats() InterceptStats
}

// InterceptStats holds statistics about intercepted traffic
type InterceptStats struct {
	TotalConnections   int64
	ActiveConnections  int64
	TotalBytesIn       int64
	TotalBytesOut      int64
	InterceptedPackets int64
	DroppedPackets     int64
}

// New creates a new platform-specific interceptor
func New(config Config, logger logger.Logger) (Interceptor, error) {
	return newPlatformInterceptor(config, logger)
}

// IsSupported returns true if OS-level interception is supported on this platform
func IsSupported() bool {
	return isPlatformSupported()
}

// RequiresPrivileges returns true if the interceptor requires elevated privileges
func RequiresPrivileges() bool {
	return requiresPlatformPrivileges()
}