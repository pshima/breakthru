//go:build windows
// +build windows

package system

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
)

const (
	internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

// EnableSystemProxy enables the Windows system proxy settings
func EnableSystemProxy(proxyServer string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	// Enable proxy
	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("failed to enable proxy: %w", err)
	}

	// Set proxy server
	if err := key.SetStringValue("ProxyServer", proxyServer); err != nil {
		return fmt.Errorf("failed to set proxy server: %w", err)
	}

	return nil
}

// DisableSystemProxy disables the Windows system proxy settings
func DisableSystemProxy() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	// Disable proxy
	if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
		return fmt.Errorf("failed to disable proxy: %w", err)
	}

	return nil
}

// GetSystemProxyStatus returns the current proxy status and server
func GetSystemProxyStatus() (enabled bool, proxyServer string, err error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE)
	if err != nil {
		return false, "", fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	// Check if proxy is enabled
	proxyEnable, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil {
		// If the value doesn't exist, proxy is disabled
		return false, "", nil
	}

	enabled = proxyEnable == 1

	// Get proxy server if enabled
	if enabled {
		proxyServer, _, err = key.GetStringValue("ProxyServer")
		if err != nil {
			// Proxy is enabled but no server is set
			return enabled, "", nil
		}
	}

	return enabled, proxyServer, nil
}