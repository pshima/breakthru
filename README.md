# breakthru

A cross-platform HTTPS/WebSocket man-in-the-middle proxy for inspecting video game network traffic. Written in Go and designed to be simple, single-binary application that "just works".

## Features

- **HTTPS Interception**: Terminates SSL connections to inspect encrypted traffic
- **WebSocket Support**: Full support for WebSocket connections (planned)
- **Cross-Platform**: Builds for macOS and Windows 11+ (x64 and ARM64)
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

## Practical Examples

### Example 1: Debugging Mobile Game API Calls

If you're trying to understand what API calls your mobile game makes:

```bash
# 1. Start breakthru on your computer
./breakthru -verbose -port 8080 -log mobile-game.log

# 2. Configure your phone's WiFi settings to use your computer as HTTP proxy:
#    - Proxy Host: Your computer's IP (e.g., 192.168.1.100)
#    - Proxy Port: 8080

# 3. Install the breakthru CA certificate on your phone (once HTTPS interception is implemented)

# 4. Launch your game and play normally
# 5. Check the log file to see all HTTP/HTTPS traffic
tail -f mobile-game.log
```

### Example 2: Analyzing PC Game Network Traffic

For PC games that respect system proxy settings:

```bash
# Create a config file for the game
cat > game-config.json << EOF
{
  "port": 8888,
  "log_file": "game-traffic.log",
  "verbose": true,
  "target_hosts": ["api.gamestudio.com", "matchmaking.gamestudio.com"],
  "buffer_size": 65536
}
EOF

# Start the proxy
./breakthru -config game-config.json

# Configure system proxy (on macOS):
# System Preferences > Network > Advanced > Proxies
# HTTP Proxy: localhost:8888
# HTTPS Proxy: localhost:8888

# Or set environment variables:
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888

# Launch your game
```

### Example 3: Monitoring Specific Game Servers

To monitor traffic only to specific game servers:

```bash
# Start with a configuration targeting specific hosts
./breakthru -port 9090 -verbose \
  -log game-traffic.log \
  -config specific-hosts.json

# specific-hosts.json:
{
  "port": 9090,
  "verbose": true,
  "target_hosts": [
    "gamedomain1.com",
    "gamedomain2.com"
  ],
  "https_mode": true
}
```

### Example 4: Running as a Windows 11 Service

#### Using Task Scheduler (Recommended):

```powershell
# Create a scheduled task to run breakthru at startup
# Open PowerShell as Administrator

# Create the task
$Action = New-ScheduledTaskAction -Execute "C:\Program Files\Breakthru\breakthru.exe" -Argument "-config C:\Program Files\Breakthru\config.json"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Breakthru Proxy" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Breakthru network proxy for game traffic analysis"

# Start the task immediately
Start-ScheduledTask -TaskName "Breakthru Proxy"

# View task status
Get-ScheduledTask -TaskName "Breakthru Proxy"
```

#### Using Windows Subsystem for Linux (WSL2):

```powershell
# Install WSL2 (Windows 11 required)
wsl --install

# After restart, configure breakthru in WSL
wsl
sudo mkdir -p /usr/local/bin
sudo cp breakthru /usr/local/bin/
sudo chmod +x /usr/local/bin/breakthru

# Create systemd service in WSL
sudo tee /etc/systemd/system/breakthru.service > /dev/null <<EOF
[Unit]
Description=Breakthru Proxy Server
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/breakthru -config /etc/breakthru/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start in WSL
sudo systemctl enable breakthru
sudo systemctl start breakthru
```

#### Using Windows Service (Advanced):

```powershell
# Using NSSM (Non-Sucking Service Manager)
# Download NSSM from https://nssm.cc/download

# Install as service
nssm install "Breakthru Proxy" "C:\Program Files\Breakthru\breakthru.exe"
nssm set "Breakthru Proxy" AppParameters "-config C:\Program Files\Breakthru\config.json"
nssm set "Breakthru Proxy" AppDirectory "C:\Program Files\Breakthru"
nssm set "Breakthru Proxy" Description "Breakthru network proxy for game traffic analysis"
nssm set "Breakthru Proxy" Start SERVICE_AUTO_START

# Start the service
nssm start "Breakthru Proxy"

# Check service status
nssm status "Breakthru Proxy"
```

#### Configuring Windows 11 System Proxy:

```powershell
# Set system-wide proxy (PowerShell as Administrator)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080"

# Or use GUI: Settings > Network & Internet > Proxy > Manual proxy setup
# HTTP Proxy: 127.0.0.1:8080
# HTTPS Proxy: 127.0.0.1:8080

# Disable proxy when done
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
```

### Example 5: Docker Container (Future)

```dockerfile
# Dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o breakthru ./cmd/breakthru

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/breakthru /usr/local/bin/
EXPOSE 8080
CMD ["breakthru"]
```

```bash
# Build and run
docker build -t breakthru .
docker run -p 8080:8080 -v $(pwd)/logs:/logs breakthru -log /logs/traffic.log
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

#### On Windows 11 (PowerShell):
```powershell
# View all HTTP requests
Select-String -Pattern "HTTP request" -Path "breakthru.log"

# Filter by specific host
Select-String -Pattern "host=api.example.com" -Path "breakthru.log"

# View only errors
Select-String -Pattern "level=ERROR" -Path "breakthru.log"

# Follow logs in real-time (PowerShell 3.0+)
Get-Content -Path "breakthru.log" -Wait -Tail 10 | Where-Object { $_ -match "CONNECT" }

# View last 50 lines
Get-Content -Path "breakthru.log" -Tail 50

# Search for specific error codes
Select-String -Pattern "code=001" -Path "breakthru.log" -Context 2,2
```

### Tips for Game Traffic Analysis

1. **Start Simple**: Begin with HTTP traffic before moving to HTTPS
2. **Use Verbose Mode**: Enable `-verbose` to see all headers and details
3. **Filter by Host**: Use the `target_hosts` config to reduce noise
4. **Timestamp Analysis**: Look for patterns in request timing
5. **Save Different Sessions**: Use different log files for different games or sessions

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