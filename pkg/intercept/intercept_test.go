package intercept

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// mockLogger implements the logger.Logger interface for testing
type mockLogger struct {
	messages []string
}

func (m *mockLogger) Info(msg string, args ...any)  { m.messages = append(m.messages, "INFO: "+msg) }
func (m *mockLogger) Debug(msg string, args ...any) { m.messages = append(m.messages, "DEBUG: "+msg) }
func (m *mockLogger) Warn(msg string, args ...any)  { m.messages = append(m.messages, "WARN: "+msg) }
func (m *mockLogger) Error(msg string, args ...any) { m.messages = append(m.messages, "ERROR: "+msg) }
func (m *mockLogger) Close() error                  { return nil }

func TestIsSupported(t *testing.T) {
	supported := IsSupported()
	
	// Should be supported on Windows, macOS, and Linux
	expectedSupported := runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux"
	
	if supported != expectedSupported {
		t.Errorf("IsSupported() = %v, want %v for OS %s", supported, expectedSupported, runtime.GOOS)
	}
}

func TestRequiresPrivileges(t *testing.T) {
	requiresPrivs := RequiresPrivileges()
	
	// Should require privileges on supported platforms
	expectedRequires := runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux"
	
	if requiresPrivs != expectedRequires {
		t.Errorf("RequiresPrivileges() = %v, want %v for OS %s", requiresPrivs, expectedRequires, runtime.GOOS)
	}
}

func TestNew(t *testing.T) {
	config := Config{
		Mode:      ModeTransparent,
		ProxyPort: 8080,
	}
	
	logger := &mockLogger{}
	
	interceptor, err := New(config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	
	if interceptor == nil {
		t.Fatal("New() returned nil interceptor")
	}
}

func TestInterceptorLifecycle(t *testing.T) {
	config := Config{
		Mode:      ModeTransparent,
		ProxyPort: 8080,
	}
	
	logger := &mockLogger{}
	
	interceptor, err := New(config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Start interceptor
	err = interceptor.Start(ctx)
	if err != nil && !IsSupported() {
		// Expected error on unsupported platforms
		t.Logf("Expected error on unsupported platform: %v", err)
		return
	} else if err != nil && IsSupported() {
		// On supported platforms, this might still fail due to lack of privileges
		t.Logf("Error starting interceptor (may need privileges): %v", err)
		return
	}
	
	// Test getting connections channel
	connections := interceptor.GetConnections()
	if connections == nil {
		t.Error("GetConnections() returned nil channel")
	}
	
	// Test stats
	stats := interceptor.GetStats()
	if stats.TotalConnections < 0 {
		t.Error("GetStats() returned negative TotalConnections")
	}
	
	// Stop interceptor
	err = interceptor.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestInterceptorDoubleStart(t *testing.T) {
	config := Config{
		Mode:      ModeTransparent,
		ProxyPort: 8080,
	}
	
	logger := &mockLogger{}
	
	interceptor, err := New(config, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Start first time
	err1 := interceptor.Start(ctx)
	if err1 != nil && !IsSupported() {
		t.Logf("Expected error on unsupported platform: %v", err1)
		return
	}
	
	// Start second time - should fail
	err2 := interceptor.Start(ctx)
	if err2 == nil && IsSupported() {
		t.Error("Expected error when starting interceptor twice")
	}
	
	// Clean up
	interceptor.Stop()
}

func TestInterceptModes(t *testing.T) {
	tests := []struct {
		name string
		mode InterceptMode
	}{
		{"Disabled", ModeDisabled},
		{"Transparent", ModeTransparent},
		{"All", ModeAll},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Mode:      tt.mode,
				ProxyPort: 8080,
			}
			
			logger := &mockLogger{}
			
			interceptor, err := New(config, logger)
			if err != nil {
				t.Fatalf("New() with mode %v error = %v", tt.mode, err)
			}
			
			if interceptor == nil {
				t.Fatalf("New() with mode %v returned nil", tt.mode)
			}
		})
	}
}

func TestConnection(t *testing.T) {
	// Test Connection struct
	conn := &Connection{
		LocalAddr:  nil,
		RemoteAddr: nil,
		Protocol:   "tcp",
		Data:       []byte("test data"),
	}
	
	if conn.Protocol != "tcp" {
		t.Errorf("Connection.Protocol = %s, want tcp", conn.Protocol)
	}
	
	if string(conn.Data) != "test data" {
		t.Errorf("Connection.Data = %s, want 'test data'", string(conn.Data))
	}
}

func TestInterceptStats(t *testing.T) {
	stats := InterceptStats{
		TotalConnections:   100,
		ActiveConnections:  5,
		TotalBytesIn:      1024,
		TotalBytesOut:     2048,
		InterceptedPackets: 150,
		DroppedPackets:    2,
	}
	
	if stats.TotalConnections != 100 {
		t.Errorf("InterceptStats.TotalConnections = %d, want 100", stats.TotalConnections)
	}
	
	if stats.ActiveConnections != 5 {
		t.Errorf("InterceptStats.ActiveConnections = %d, want 5", stats.ActiveConnections)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid transparent config",
			config: Config{
				Mode:      ModeTransparent,
				ProxyPort: 8080,
			},
			valid: true,
		},
		{
			name: "valid with ports",
			config: Config{
				Mode:         ModeTransparent,
				ProxyPort:    8080,
				IncludePorts: []int{80, 443},
				ExcludePorts: []int{22, 25},
			},
			valid: true,
		},
		{
			name: "disabled mode",
			config: Config{
				Mode:      ModeDisabled,
				ProxyPort: 8080,
			},
			valid: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{}
			
			_, err := New(tt.config, logger)
			hasError := err != nil
			
			if tt.valid && hasError {
				t.Errorf("Expected valid config but got error: %v", err)
			}
			if !tt.valid && !hasError {
				t.Error("Expected invalid config but got no error")
			}
		})
	}
}