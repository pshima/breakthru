//go:build !windows && !darwin
// +build !windows,!darwin

package system

import "fmt"

// EnableSystemProxy enables the system proxy settings (not implemented for non-Windows/macOS)
func EnableSystemProxy(proxyServer string) error {
	return fmt.Errorf("system proxy configuration is only supported on Windows and macOS")
}

// DisableSystemProxy disables the system proxy settings (not implemented for non-Windows/macOS)
func DisableSystemProxy() error {
	return fmt.Errorf("system proxy configuration is only supported on Windows and macOS")
}

// GetSystemProxyStatus returns the current proxy status (not implemented for non-Windows/macOS)
func GetSystemProxyStatus() (enabled bool, proxyServer string, err error) {
	return false, "", fmt.Errorf("system proxy configuration is only supported on Windows and macOS")
}