//go:build !linux

package intercept

import (
	"github.com/pshima/breakthru/internal/logger"
)

// newLinuxInterceptor creates a stub Linux interceptor on non-Linux platforms
func newLinuxInterceptor(config Config, logger logger.Logger) (Interceptor, error) {
	return newUnsupportedInterceptor(config, logger)
}