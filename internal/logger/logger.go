package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger provides structured logging with error codes
type Logger interface {
	Info(msg string, args ...any)
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Close() error
}

// Config holds logger configuration
type Config struct {
	FilePath string
	Verbose  bool
}

type logger struct {
	slog     *slog.Logger
	file     *os.File
	mu       sync.Mutex
	verbose  bool
}

// New creates a new logger instance with file and console output
func New(cfg Config) (Logger, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	multiWriter := io.MultiWriter(os.Stdout, file)
	
	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, time.Now().Format("2006-01-02 15:04:05.000"))
			}
			return a
		},
	}

	handler := slog.NewTextHandler(multiWriter, opts)
	slogger := slog.New(handler)

	return &logger{
		slog:    slogger,
		file:    file,
		verbose: cfg.Verbose,
	}, nil
}

// Info logs informational messages
func (l *logger) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Info(msg, args...)
}

// Debug logs debug messages (only when verbose is enabled)
func (l *logger) Debug(msg string, args ...any) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Debug(msg, args...)
}

// Warn logs warning messages
func (l *logger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Warn(msg, args...)
}

// Error logs error messages with error codes
func (l *logger) Error(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Error(msg, args...)
}

// Close closes the log file
func (l *logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}