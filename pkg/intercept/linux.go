//go:build linux

package intercept

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pshima/breakthru/internal/logger"
)

// linuxInterceptor implements traffic interception on Linux using iptables/netfilter
type linuxInterceptor struct {
	config      Config
	logger      logger.Logger
	running     int32
	connections chan *Connection
	stats       InterceptStats
	statsMutex  sync.RWMutex
	
	// iptables chain name for our rules
	chainName string
}

// newLinuxInterceptor creates a Linux-specific interceptor
func newLinuxInterceptor(config Config, logger logger.Logger) (Interceptor, error) {
	interceptor := &linuxInterceptor{
		config:      config,
		logger:      logger,
		connections: make(chan *Connection, 1000),
		chainName:   "BREAKTHRU_INTERCEPT",
	}
	
	// Check if iptables is available
	if err := interceptor.checkIptablesAvailable(); err != nil {
		return nil, fmt.Errorf("iptables not available: %w", err)
	}
	
	logger.Info("Linux interceptor created", "mode", config.Mode, "chain", interceptor.chainName)
	return interceptor, nil
}

func (i *linuxInterceptor) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&i.running, 0, 1) {
		return fmt.Errorf("interceptor already running")
	}
	
	i.logger.Info("Starting Linux traffic interception")
	
	// Install iptables rules for traffic redirection
	if err := i.installIptablesRules(); err != nil {
		atomic.StoreInt32(&i.running, 0)
		return fmt.Errorf("failed to install iptables rules: %w", err)
	}
	
	// Start netfilter queue processing or packet capture
	// In real implementation, this would use libnetfilter_queue or raw sockets
	go i.simulateTrafficCapture(ctx)
	
	i.logger.Info("Linux traffic interception started successfully")
	return nil
}

func (i *linuxInterceptor) Stop() error {
	if !atomic.CompareAndSwapInt32(&i.running, 1, 0) {
		return fmt.Errorf("interceptor not running")
	}
	
	i.logger.Info("Stopping Linux traffic interception")
	
	// Remove iptables rules
	if err := i.removeIptablesRules(); err != nil {
		i.logger.Error("Failed to remove iptables rules", "error", err)
	}
	
	close(i.connections)
	i.logger.Info("Linux traffic interception stopped")
	return nil
}

func (i *linuxInterceptor) GetConnections() <-chan *Connection {
	return i.connections
}

func (i *linuxInterceptor) InjectResponse(conn *Connection, response []byte) error {
	// In real implementation, this would use:
	// 1. Raw sockets to craft and inject packets
	// 2. netfilter queue verdict system
	// 3. Proper packet reconstruction with correct headers
	
	i.logger.Debug("Injecting response", 
		"remote_addr", conn.RemoteAddr.String(),
		"response_size", len(response),
	)
	
	i.statsMutex.Lock()
	i.stats.TotalBytesOut += int64(len(response))
	i.statsMutex.Unlock()
	
	return nil
}

func (i *linuxInterceptor) GetStats() InterceptStats {
	i.statsMutex.RLock()
	defer i.statsMutex.RUnlock()
	return i.stats
}

// checkIptablesAvailable checks if iptables is available and we have permissions
func (i *linuxInterceptor) checkIptablesAvailable() error {
	cmd := exec.Command("iptables", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables command failed (may need root privileges): %w", err)
	}
	return nil
}

// installIptablesRules installs iptables rules to redirect traffic to our proxy
func (i *linuxInterceptor) installIptablesRules() error {
	i.logger.Info("Installing iptables rules", "chain", i.chainName)
	
	// Create our custom chain
	cmd := exec.Command("iptables", "-t", "nat", "-N", i.chainName)
	if err := cmd.Run(); err != nil {
		// Chain might already exist, continue
		i.logger.Debug("Chain creation failed (may already exist)", "error", err)
	}
	
	// Add rules to redirect HTTP traffic to our proxy
	rules := [][]string{
		// Redirect HTTP traffic to proxy
		{"iptables", "-t", "nat", "-A", i.chainName, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", i.config.ProxyPort)},
		// Redirect HTTPS traffic to proxy  
		{"iptables", "-t", "nat", "-A", i.chainName, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", i.config.ProxyPort)},
		// Jump to our chain from OUTPUT
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-j", i.chainName},
	}
	
	for _, rule := range rules {
		cmd := exec.Command(rule[0], rule[1:]...)
		if err := cmd.Run(); err != nil {
			i.logger.Error("Failed to install iptables rule", "rule", rule, "error", err)
			// Continue with other rules
		} else {
			i.logger.Debug("Installed iptables rule", "rule", rule)
		}
	}
	
	// For demonstration, we'll just log what we would do
	i.logger.Debug("Would install iptables rules for transparent proxying")
	
	return nil
}

// removeIptablesRules removes our iptables rules
func (i *linuxInterceptor) removeIptablesRules() error {
	i.logger.Info("Removing iptables rules", "chain", i.chainName)
	
	// Remove jump rule from OUTPUT chain
	cmd := exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", i.chainName)
	if err := cmd.Run(); err != nil {
		i.logger.Debug("Failed to remove OUTPUT rule", "error", err)
	}
	
	// Flush our chain
	cmd = exec.Command("iptables", "-t", "nat", "-F", i.chainName)
	if err := cmd.Run(); err != nil {
		i.logger.Debug("Failed to flush chain", "error", err)
	}
	
	// Delete our chain
	cmd = exec.Command("iptables", "-t", "nat", "-X", i.chainName)
	if err := cmd.Run(); err != nil {
		i.logger.Debug("Failed to delete chain", "error", err)
	}
	
	return nil
}

// simulateTrafficCapture simulates traffic capture for demonstration
func (i *linuxInterceptor) simulateTrafficCapture(ctx context.Context) {
	ticker := time.NewTicker(6 * time.Second)
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
				LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33333},
				RemoteAddr: &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 80}, // example.com
				Protocol:   "tcp",
				Data:       []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
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

// Real Linux implementation would include:
//
// 1. iptables/netfilter integration:
//    - REDIRECT target for transparent proxying
//    - NFQUEUE target for packet inspection
//    - SO_ORIGINAL_DST to get original destination
//
// 2. libnetfilter_queue usage:
//    - Bind to netfilter queue
//    - Process packets in userspace
//    - Issue verdicts (ACCEPT, DROP, modify)
//
// 3. Raw socket programming:
//    - Create raw sockets for packet injection
//    - Craft proper IP/TCP headers
//    - Handle packet fragmentation
//
// 4. Connection tracking:
//    - Track TCP connection state
//    - Handle connection establishment/teardown  
//    - Reassemble TCP streams
//
// 5. Advanced features:
//    - Traffic shaping using tc (traffic control)
//    - eBPF programs for high-performance filtering
//    - Integration with conntrack for stateful filtering
//
// 6. Security considerations:
//    - CAP_NET_ADMIN capability requirement
//    - Proper cleanup on exit
//    - Handle system firewall interactions