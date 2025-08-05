//go:build !darwin

package intercept

import (
	"github.com/pshima/breakthru/internal/logger"
)

// newDarwinInterceptor creates a stub Darwin interceptor on non-Darwin platforms
func newDarwinInterceptor(config Config, logger logger.Logger) (Interceptor, error) {
	return newUnsupportedInterceptor(config, logger)
}