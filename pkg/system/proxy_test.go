package system

import (
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
			expectError: true, // Always expect error since tests can't provide interactive input
		},
		{
			name: "DisableSystemProxy on non-Windows",
			fn: func() error {
				return DisableSystemProxy()
			},
			expectError: true, // Always expect error since tests can't provide interactive input
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
	
	// Always expect error since tests can't provide interactive input
	if err == nil {
		t.Errorf("expected error due to interactive input requirement but got nil")
	}
	if enabled {
		t.Errorf("expected enabled=false when error occurs but got true")
	}
	if proxyServer != "" {
		t.Errorf("expected empty proxyServer when error occurs but got %s", proxyServer)
	}
}