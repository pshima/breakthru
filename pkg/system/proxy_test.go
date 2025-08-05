package system

import (
	"runtime"
	"testing"
)

func TestProxyFunctions(t *testing.T) {
	tests := []struct {
		name        string
		fn          func() error
		expectError bool
	}{
		{
			name: "EnableSystemProxy on non-Windows",
			fn: func() error {
				return EnableSystemProxy("127.0.0.1:8080")
			},
			expectError: runtime.GOOS != "windows",
		},
		{
			name: "DisableSystemProxy on non-Windows",
			fn: func() error {
				return DisableSystemProxy()
			},
			expectError: runtime.GOOS != "windows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if tt.expectError && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestGetSystemProxyStatus(t *testing.T) {
	enabled, proxyServer, err := GetSystemProxyStatus()
	
	if runtime.GOOS != "windows" {
		if err == nil {
			t.Errorf("expected error on non-Windows system but got nil")
		}
		if enabled {
			t.Errorf("expected enabled=false on non-Windows system but got true")
		}
		if proxyServer != "" {
			t.Errorf("expected empty proxyServer on non-Windows system but got %s", proxyServer)
		}
	}
}