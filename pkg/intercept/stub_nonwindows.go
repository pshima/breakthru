//go:build !windows

package intercept

import (
	"github.com/pshima/breakthru/internal/logger"
)

// newWindowsInterceptor creates a stub Windows interceptor on non-Windows platforms
func newWindowsInterceptor(config Config, logger logger.Logger) (Interceptor, error) {
	return newUnsupportedInterceptor(config, logger)
}