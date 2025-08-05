# breakthru

A cross-platform HTTPS/WebSocket man-in-the-middle proxy for inspecting video game network traffic. Written in Go and designed to be simple, single-binary application that "just works".

## Features

- **🔒 HTTPS Interception**: Full man-in-the-middle HTTPS proxy with dynamic certificate generation
- **🔐 Certificate Management**: Automatic CA generation and certificate signing for intercepted domains
- **🌐 WebSocket Support**: Complete WebSocket upgrade handling and frame inspection
- **🔍 Transparent Mode**: OS-level traffic interception for capturing ALL network traffic including HTTPS
- **📱 Cross-Platform**: Supports Windows, macOS, and Linux (x64 and ARM64)
- **⚙️ Auto-Configuration**: Automatic system proxy setup with `--enable`/`--disable` flags  
- **📊 Comprehensive Logging**: Structured logging with error codes and decrypted HTTPS traffic inspection
- **🎯 Game-Friendly**: Captures traffic from games that ignore proxy settings
- **📦 Single Binary**: No dependencies, just download and run
- **🔧 Configurable**: Domain-based filtering for selective HTTPS interception

## Installation

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

# Enable system proxy (Windows/macOS)
./breakthru -enable -port 8080

# Disable system proxy (Windows/macOS)  
./breakthru -disable
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
-enable          Enable system proxy (Windows/macOS)
-disable         Disable system proxy (Windows/macOS)
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
  "buffer_size": 32768,
  
  // HTTPS Interception Settings
  "https_interception": true,
  "https_transparent": false,
  "https_skip_verify": false,
  "https_log_bodies": true,
  "https_max_body_size": 1048576,
  
  // Certificate Management
  "cert_store_dir": "./certs",
  "auto_generate_ca": true,
  "ca_cert": "/path/to/ca-cert.pem",
  "ca_key": "/path/to/ca-key.pem",
  "cert_validity_days": 365,
  "cert_key_size": 2048,
  "cert_cleanup_enabled": true,
  "cert_cleanup_max_age_days": 30,
  
  // Domain Filtering
  "https_bypass_domains": ["banking.com", "*.gov"],
  "https_only_domains": ["api.example.com", "*.game-api.com"],
  
  "target_hosts": ["api.example.com", "game.example.com"]
}
```

## HTTPS Interception Setup

Breakthru can intercept and decrypt HTTPS traffic by acting as a man-in-the-middle proxy. This requires installing a custom CA certificate.

### Quick Start with HTTPS Interception

```bash
# 1. Create a configuration file for HTTPS interception
cat > https-config.json << EOF
{
  "port": 8888,
  "log_file": "game-traffic.log",
  "verbose": true,
  "https_interception": true,
  "auto_generate_ca": true,
  "cert_store_dir": "./certs",
  "https_log_bodies": true,
  "https_only_domains": ["api.gamestudio.com", "*.game-servers.com"],
  "https_bypass_domains": ["banking.com", "*.financial.com"],
  "buffer_size": 65536
}
EOF

# 2. Start the proxy (will auto-generate CA certificate)
./breakthru -config https-config.json

# 3. Install the CA certificate in your system/browser
# The CA certificate will be created at: ./certs/ca.crt

# 4. Configure system proxy or browser to use localhost:8888

# 5. Launch your game - HTTPS traffic will now be decrypted and logged
```

### Installing the CA Certificate

For HTTPS interception to work, you must install the generated CA certificate:

**Windows:**
```bash
# Import the CA certificate into Windows certificate store
certlm.msc
# Navigate to Trusted Root Certification Authorities > Certificates
# Right-click > All Tasks > Import > Select ./certs/ca.crt
```

**macOS:**
```bash
# Add to keychain and trust
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./certs/ca.crt
```

**Linux (Firefox):**
```bash
# Firefox: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import
# Select ./certs/ca.crt and check "Trust this CA to identify websites"
```

### Game Traffic Monitoring Example

```bash
# Monitor API calls in real-time
tail -f game-traffic.log | grep "api.gamestudio.com"

# Extract all JSON responses
grep "response_body" game-traffic.log | jq '.'

# Find authentication requests
grep -E "login|auth|token" game-traffic.log
```

#### Configuring System Proxy:

##### Automatic Configuration (Recommended):

**Windows:**
```bash
# Enable Windows system proxy
./breakthru.exe -enable -port 8080

# Disable Windows system proxy when done
./breakthru.exe -disable
```

**macOS:**
```bash
# Enable macOS system proxy (will prompt for network service selection)
./breakthru -enable -port 8080

# Disable macOS system proxy (will prompt for network service selection)
./breakthru -disable
```

Note: On macOS, you'll be prompted to select which network service (Wi-Fi, Ethernet, etc.) to configure. Admin privileges (sudo) are required.

##### Manual Configuration:

**Windows (PowerShell as Administrator):**
```powershell
# Set system-wide proxy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080"

# Or use GUI: Settings > Network & Internet > Proxy > Manual proxy setup
# HTTP Proxy: 127.0.0.1:8080
# HTTPS Proxy: 127.0.0.1:8080

# Disable proxy when done
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
```

**macOS (Terminal):**
```bash
# Enable proxy for Wi-Fi
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080 off
sudo networksetup -setwebproxystate "Wi-Fi" on
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080 off
sudo networksetup -setsecurewebproxystate "Wi-Fi" on

# Disable proxy for Wi-Fi
sudo networksetup -setwebproxystate "Wi-Fi" off
sudo networksetup -setsecurewebproxystate "Wi-Fi" off

# Check proxy status
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"
```

### Reading the Logs

The proxy logs all traffic in a structured format. Here's how to analyze them:

#### On macOS/Unix:
```bash
# View all HTTP requests
grep "HTTP request" breakthru.log

# Filter by specific host
grep "host=api.example.com" breakthru.log

# View only errors
grep "level=ERROR" breakthru.log

# Follow logs in real-time with filtering
tail -f breakthru.log | grep "CONNECT"

# Pretty print JSON responses (once implemented)
cat breakthru.log | grep "response_body" | jq '.'
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

**✅ Production Ready Features:**
- ✅ **HTTP/HTTPS Proxy**: Complete proxy server with connection pooling and keep-alive support
- ✅ **HTTPS Interception**: Full man-in-the-middle HTTPS proxy with dynamic certificate generation
- ✅ **Certificate Management**: Automatic CA generation, certificate signing, and cleanup
- ✅ **TLS SNI Extraction**: Server Name Indication parsing from TLS handshakes
- ✅ **WebSocket Support**: Complete WebSocket upgrade handling and frame inspection
- ✅ **Transparent Mode**: OS-level traffic interception for capturing ALL network traffic
- ✅ **Configuration System**: Comprehensive JSON configuration with domain filtering
- ✅ **Logging Infrastructure**: Structured logging with error codes and comprehensive test coverage

**🔧 Advanced Configuration Options:**
- Domain-based HTTPS interception filtering (whitelist/blacklist)
- Configurable certificate validity and key sizes
- Request/response body logging with size limits
- Certificate cleanup and management
- Transparent proxy port filtering

## Roadmap

- [ ] Web UI for traffic inspection and analysis
- [ ] Request/response modification and replay
- [ ] Traffic filtering and search capabilities
- [ ] Plugin system for custom traffic analysis
- [ ] Performance optimizations for high-traffic scenarios
- [ ] Mobile device support and configuration
- [ ] Integration with popular reverse engineering tools

## License

[MIT License](LICENSE)

## Acknowledgments

Inspired by [mitmproxy](https://github.com/mitmproxy/mitmproxy)