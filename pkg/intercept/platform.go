package intercept

import (
	"runtime"

	"github.com/pshima/breakthru/internal/logger"
)

// newPlatformInterceptor creates a platform-specific interceptor
func newPlatformInterceptor(config Config, logger logger.Logger) (Interceptor, error) {
	switch runtime.GOOS {
	case "windows":
		return newWindowsInterceptor(config, logger)
	case "darwin":
		return newDarwinInterceptor(config, logger)
	case "linux":
		return newLinuxInterceptor(config, logger)
	default:
		return newUnsupportedInterceptor(config, logger)
	}
}

// isPlatformSupported returns true if the current platform supports interception
func isPlatformSupported() bool {
	switch runtime.GOOS {
	case "windows", "darwin", "linux":
		return true
	default:
		return false
	}
}

// requiresPlatformPrivileges returns true if elevated privileges are required
func requiresPlatformPrivileges() bool {
	switch runtime.GOOS {
	case "windows":
		return true // Requires administrator privileges for WinDivert
	case "darwin":
		return true // Requires root for pfctl or Network Extensions
	case "linux":
		return true // Requires root for iptables/netfilter
	default:
		return false
	}
}