package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				FilePath: filepath.Join(t.TempDir(), "test.log"),
				Verbose:  false,
			},
			wantErr: false,
		},
		{
			name: "verbose mode",
			config: Config{
				FilePath: filepath.Join(t.TempDir(), "test-verbose.log"),
				Verbose:  true,
			},
			wantErr: false,
		},
		{
			name: "creates directory if not exists",
			config: Config{
				FilePath: filepath.Join(t.TempDir(), "subdir", "test.log"),
				Verbose:  false,
			},
			wantErr: false,
		},
		{
			name: "invalid file path",
			config: Config{
				FilePath: "/invalid\x00path/test.log",
				Verbose:  false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := New(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				defer logger.Close()
			}
		})
	}
}

func TestLogger_Logging(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "test-logging.log")
	logger, err := New(Config{
		FilePath: logFile,
		Verbose:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Test all log levels
	logger.Info("test info message", "key", "value")
	logger.Debug("test debug message", "key", "value")
	logger.Warn("test warn message", "key", "value")
	logger.Error("test error message", "key", "value", "code", "001")

	// Give time for writes to flush
	time.Sleep(10 * time.Millisecond)

	// Verify log file was created and contains expected content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)
	expectedMessages := []string{
		"test info message",
		"test debug message",
		"test warn message",
		"test error message",
		"key=value",
		"code=001",
	}

	for _, expected := range expectedMessages {
		if !strings.Contains(logContent, expected) {
			t.Errorf("Log file missing expected content: %s", expected)
		}
	}
}

func TestLogger_NonVerboseMode(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "test-non-verbose.log")
	logger, err := New(Config{
		FilePath: logFile,
		Verbose:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Debug messages should not appear in non-verbose mode
	logger.Debug("this should not appear", "key", "value")
	logger.Info("this should appear", "key", "value")

	// Give time for writes to flush
	time.Sleep(10 * time.Millisecond)

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)
	if strings.Contains(logContent, "this should not appear") {
		t.Error("Debug message appeared in non-verbose mode")
	}
	if !strings.Contains(logContent, "this should appear") {
		t.Error("Info message missing from log")
	}
}

func TestLogger_Close(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "test-close.log")
	logger, err := New(Config{
		FilePath: logFile,
		Verbose:  false,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Write a message
	logger.Info("test message before close")

	// Close should not return error
	if err := logger.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify file still exists after close
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file was removed after close")
	}
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "test-concurrent.log")
	logger, err := New(Config{
		FilePath: logFile,
		Verbose:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.Info("concurrent message", "goroutine", id)
			logger.Debug("concurrent debug", "goroutine", id)
			logger.Warn("concurrent warn", "goroutine", id)
			logger.Error("concurrent error", "goroutine", id, "code", "002")
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Give time for writes to flush
	time.Sleep(50 * time.Millisecond)

	// Verify file exists and has content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty after concurrent writes")
	}
}