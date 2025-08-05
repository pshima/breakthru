//go:build darwin

package intercept

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pshima/breakthru/internal/logger"
)

// darwinInterceptor implements traffic interception on macOS using pfctl
type darwinInterceptor struct {
	config      Config
	logger      logger.Logger
	running     int32
	connections chan *Connection
	stats       InterceptStats
	statsMutex  sync.RWMutex
	
	// pfctl anchor name for our rules
	anchorName string
}

// newDarwinInterceptor creates a macOS-specific interceptor
func newDarwinInterceptor(config Config, logger logger.Logger) (Interceptor, error) {
	interceptor := &darwinInterceptor{
		config:      config,
		logger:      logger,
		connections: make(chan *Connection, 1000),
		anchorName:  "breakthru_intercept",
	}
	
	logger.Info("macOS interceptor created", "mode", config.Mode, "anchor", interceptor.anchorName)
	return interceptor, nil
}

func (i *darwinInterceptor) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&i.running, 0, 1) {
		return fmt.Errorf("interceptor already running")
	}
	
	i.logger.Info("Starting macOS traffic interception")
	
	// Check if pfctl is available
	if err := i.checkPfctlAvailable(); err != nil {
		atomic.StoreInt32(&i.running, 0)
		return fmt.Errorf("pfctl not available: %w", err)
	}
	
	// Install pfctl rules for traffic redirection
	if err := i.installPfRules(); err != nil {
		atomic.StoreInt32(&i.running, 0)
		return fmt.Errorf("failed to install pf rules: %w", err)
	}
	
	// Start packet capture simulation
	// In real implementation, this would use packet capture or divert sockets
	go i.simulateTrafficCapture(ctx)
	
	i.logger.Info("macOS traffic interception started successfully")
	return nil
}

func (i *darwinInterceptor) Stop() error {
	if !atomic.CompareAndSwapInt32(&i.running, 1, 0) {
		return fmt.Errorf("interceptor not running")
	}
	
	i.logger.Info("Stopping macOS traffic interception")
	
	// Remove pfctl rules
	if err := i.removePfRules(); err != nil {
		i.logger.Error("Failed to remove pf rules", "error", err)
	}
	
	close(i.connections)
	i.logger.Info("macOS traffic interception stopped")
	return nil
}

func (i *darwinInterceptor) GetConnections() <-chan *Connection {
	return i.connections
}

func (i *darwinInterceptor) InjectResponse(conn *Connection, response []byte) error {
	// In real implementation, this would use raw sockets or divert sockets
	// to inject packets back into the network stack
	
	i.logger.Debug("Injecting response", 
		"remote_addr", conn.RemoteAddr.String(),
		"response_size", len(response),
	)
	
	i.statsMutex.Lock()
	i.stats.TotalBytesOut += int64(len(response))
	i.statsMutex.Unlock()
	
	return nil
}

func (i *darwinInterceptor) GetStats() InterceptStats {
	i.statsMutex.RLock()
	defer i.statsMutex.RUnlock()
	return i.stats
}

// checkPfctlAvailable checks if pfctl is available and we have permissions
func (i *darwinInterceptor) checkPfctlAvailable() error {
	cmd := exec.Command("pfctl", "-s", "info")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl command failed (may need root privileges): %w", err)
	}
	return nil
}

// installPfRules installs pfctl rules to redirect traffic to our proxy
func (i *darwinInterceptor) installPfRules() error {
	i.logger.Info("Installing pfctl rules", "anchor", i.anchorName)
	
	// Create pfctl rules for transparent proxying
	rules := fmt.Sprintf(`
# Breakthru transparent proxy rules
anchor "%s"
load anchor "%s" from "/dev/stdin"

# Rules for anchor %s
rdr on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port %d
rdr on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port %d
pass in on lo0 inet proto tcp from any to 127.0.0.1 port %d
pass out on lo0 inet proto tcp from 127.0.0.1 port %d to any
`, i.anchorName, i.anchorName, i.anchorName, i.config.ProxyPort, i.config.ProxyPort, i.config.ProxyPort, i.config.ProxyPort)
	
	// In real implementation:
	// 1. Write rules to temporary file
	// 2. Load rules using pfctl -f
	// 3. Enable pf if not already enabled
	
	cmd := exec.Command("pfctl", "-a", i.anchorName, "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(`
rdr on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port %d
rdr on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port %d
pass in on lo0 inet proto tcp from any to 127.0.0.1 port %d
pass out on lo0 inet proto tcp from 127.0.0.1 port %d to any
`, i.config.ProxyPort, i.config.ProxyPort, i.config.ProxyPort, i.config.ProxyPort))
	
	// For demonstration, we'll just log what we would do
	i.logger.Debug("Would install pfctl rules", "rules", rules)
	
	return nil
}

// removePfRules removes our pfctl rules
func (i *darwinInterceptor) removePfRules() error {
	i.logger.Info("Removing pfctl rules", "anchor", i.anchorName)
	
	// Remove our anchor rules
	cmd := exec.Command("pfctl", "-a", i.anchorName, "-F", "all")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush pfctl anchor: %w", err)
	}
	
	return nil
}

// simulateTrafficCapture simulates traffic capture for demonstration
func (i *darwinInterceptor) simulateTrafficCapture(ctx context.Context) {
	ticker := time.NewTicker(7 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&i.running) == 0 {
				return
			}
			
			// Simulate intercepting a connection
			conn := &Connection{
				LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321},
				RemoteAddr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443},
				Protocol:   "tcp",
				Data:       []byte("GET /api/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
			}
			
			select {
			case i.connections <- conn:
				i.statsMutex.Lock()
				i.stats.TotalConnections++
				i.stats.ActiveConnections++
				i.stats.TotalBytesIn += int64(len(conn.Data))
				i.stats.InterceptedPackets++
				i.statsMutex.Unlock()
				
				i.logger.Debug("Intercepted connection", 
					"local", conn.LocalAddr.String(),
					"remote", conn.RemoteAddr.String(),
					"protocol", conn.Protocol,
					"data_size", len(conn.Data),
				)
			default:
				i.statsMutex.Lock()
				i.stats.DroppedPackets++
				i.statsMutex.Unlock()
			}
		}
	}
}

// Real macOS implementation would include:
//
// 1. pfctl rule management:
//    - Dynamic rule creation/removal
//    - Handle existing pf configurations
//    - Proper anchor management
//
// 2. Packet capture using:
//    - Berkeley Packet Filter (BPF)
//    - libpcap for packet capture
//    - Raw sockets for packet injection
//
// 3. Network Extensions (modern approach):
//    - Packet Tunnel Provider
//    - App Proxy Provider
//    - Content Filter Provider
//
// 4. Transparent proxy features:
//    - Original destination retrieval using SO_ORIGINAL_DST
//    - Connection state tracking
//    - Proper packet modification
//
// 5. Security considerations:
//    - Code signing requirements
//    - System Integrity Protection (SIP)
//    - Entitlements for network access