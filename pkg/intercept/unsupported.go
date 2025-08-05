package intercept

import (
	"context"
	"fmt"
	"runtime"

	"github.com/pshima/breakthru/internal/logger"
)

// unsupportedInterceptor is a no-op interceptor for unsupported platforms
type unsupportedInterceptor struct {
	config Config
	logger logger.Logger
}

// newUnsupportedInterceptor creates an interceptor for unsupported platforms
func newUnsupportedInterceptor(config Config, logger logger.Logger) (Interceptor, error) {
	return &unsupportedInterceptor{
		config: config,
		logger: logger,
	}, nil
}

func (i *unsupportedInterceptor) Start(ctx context.Context) error {
	return fmt.Errorf("traffic interception not supported on %s", runtime.GOOS)
}

func (i *unsupportedInterceptor) Stop() error {
	return nil
}

func (i *unsupportedInterceptor) GetConnections() <-chan *Connection {
	// Return a closed channel
	ch := make(chan *Connection)
	close(ch)
	return ch
}

func (i *unsupportedInterceptor) InjectResponse(conn *Connection, response []byte) error {
	return fmt.Errorf("traffic interception not supported on %s", runtime.GOOS)
}

func (i *unsupportedInterceptor) GetStats() InterceptStats {
	return InterceptStats{}
}