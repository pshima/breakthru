# breakthru

A cross-platform HTTPS/WebSocket man-in-the-middle proxy for inspecting video game network traffic. Written in Go and designed to be simple, single-binary application that "just works".

## Features

- **HTTPS Interception**: Terminates SSL connections to inspect encrypted traffic
- **WebSocket Support**: Full support for WebSocket connections (planned)
- **Cross-Platform**: Builds for macOS, Windows, and Linux (x64 and ARM64)
- **Simple Configuration**: Use command-line flags or JSON configuration file
- **Comprehensive Logging**: Detailed logging with error codes for easy debugging
- **Single Binary**: No dependencies, just download and run

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/pshima/breakthru/releases).

### Build from Source

Requirements:
- Go 1.22 or later
- Make (optional, for using Makefile)

```bash
# Clone the repository
git clone https://github.com/pshima/breakthru.git
cd breakthru

# Build for your current platform
make build-local

# Or build for all platforms
make build

# Install to /usr/local/bin (Unix-like systems)
make install
```

## Usage

### Basic Usage

```bash
# Start the proxy on default port 8080
./breakthru

# Start with verbose logging
./breakthru -verbose

# Use a different port
./breakthru -port 9090

# Use a configuration file
./breakthru -config config.json
```

### Command-Line Options

```
-config string    Path to configuration file
-port int        Proxy port (default 8080)
-cert string     Path to certificate file
-key string      Path to key file
-log string      Path to log file (default "breakthru.log")
-verbose         Enable verbose logging
-version         Show version information
```

### Configuration File

Create a JSON configuration file for more advanced settings:

```json
{
  "port": 8080,
  "cert_file": "/path/to/cert.pem",
  "key_file": "/path/to/key.pem",
  "log_file": "breakthru.log",
  "verbose": false,
  "https_mode": true,
  "ca_cert": "/path/to/ca-cert.pem",
  "ca_key": "/path/to/ca-key.pem",
  "target_hosts": ["api.example.com", "game.example.com"],
  "buffer_size": 32768
}
```

## Development

### Project Structure

```
breakthru/
├── cmd/breakthru/        # Application entry point
├── internal/             # Internal packages
│   ├── config/          # Configuration handling
│   ├── handlers/        # HTTP handlers
│   ├── logger/          # Logging infrastructure
│   ├── models/          # Data models
│   ├── proxy/           # Proxy server implementation
│   └── services/        # Business logic
├── pkg/                 # Public packages
│   ├── certificates/    # Certificate management
│   └── utils/          # Utility functions
├── test/               # Tests
│   ├── unit/          # Unit tests
│   └── integration/   # Integration tests
└── docs/              # Documentation
```

### Building

```bash
# Run tests
make test

# Format code
make fmt

# Run linter (requires golangci-lint)
make lint

# Build for all platforms
make build

# Create release artifacts
make release
```

### Debugging

The application includes comprehensive logging with unique error codes:

- **001**: Configuration loading error
- **002**: Proxy server creation error
- **003**: Proxy server runtime error
- **004**: Server startup error
- **005**: Shutdown error

Enable verbose logging with `-verbose` flag to see detailed debug information.

## Current Status

This is an early development version. Currently implemented:
- Basic project structure
- Configuration management
- Logging infrastructure
- HTTP proxy server skeleton

## Roadmap

- [ ] HTTPS interception with certificate generation
- [ ] HTTP request/response forwarding
- [ ] WebSocket support
- [ ] OS-level traffic routing
- [ ] Certificate management utilities
- [ ] Web UI for traffic inspection
- [ ] Request/response modification
- [ ] Traffic filtering and search

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)

## Acknowledgments

Inspired by [mitmproxy](https://github.com/mitmproxy/mitmproxy)