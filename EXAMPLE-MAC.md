# Example: Monitoring Game Traffic for FunGame2

This example walks through setting up breakthru to monitor all HTTP/HTTPS traffic between a desktop game (FunGame2) and its servers at fungame2.com on macOS.

## Scenario

- **Game**: FunGame2 (desktop application)
- **Target Domain**: fungame2.com (and all subdomains)
- **Platform**: macOS with admin privileges
- **Goal**: Monitor all HTTP/HTTPS requests and responses in real-time

## Prerequisites

- macOS with admin privileges
- Command line comfort level
- Willingness to install a custom CA certificate

## Step-by-Step Setup

### 1. Build the Application

First, build breakthru for your local platform:

```bash
make build-local
```

Expected output:
```
Building for local architecture...
go build -ldflags "-X main.version=c260eb6-dirty -X main.buildTime=2025-08-05_10:15:42" -o build/bin/breakthru ./cmd/breakthru
```

### 2. Create Game-Specific Configuration

Create a configuration file tailored for monitoring FunGame2:

```bash
cat > fungame2-config.json << EOF
{
  "port": 8888,
  "log_file": "fungame2-traffic.log",
  "verbose": true,
  "https_interception": true,
  "auto_generate_ca": true,
  "cert_store_dir": "./certs",
  "https_log_bodies": true,
  "https_only_domains": ["fungame2.com", "*.fungame2.com"],
  "buffer_size": 65536,
  "https_max_body_size": 10485760
}
EOF
```

**Configuration Details:**
- `port: 8888` - Proxy listens on port 8888
- `https_only_domains` - Only intercept HTTPS for fungame2.com domains
- `https_log_bodies: true` - Log full request/response bodies
- `https_max_body_size: 10485760` - Log bodies up to 10MB

### 3. Start the Proxy Server

Launch breakthru with the game configuration:

```bash
./build/bin/breakthru -config fungame2-config.json
```

Expected output:
```
time="2025-08-05 10:15:59.803" level=INFO msg="Starting breakthru proxy" version=c260eb6-dirty
time="2025-08-05 10:15:59.804" level=INFO msg="CA loaded successfully" cert_path=./certs/ca.crt
time="2025-08-05 10:15:59.805" level=INFO msg="Starting proxy server" port=8888
```

Keep this terminal open - the proxy server is now running.

### 4. Install the CA Certificate

The proxy automatically generates a CA certificate. Install it in macOS:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./certs/ca.crt
```

You'll be prompted for your admin password. This allows breakthru to decrypt HTTPS traffic.

### 5. Configure System Proxy

**Option A - Automatic Configuration (Recommended):**

```bash
./build/bin/breakthru -enable -port 8888
```

You'll see a list of network services. Select your active connection (usually Wi-Fi):
```
Available network services:
1. USB 10/100/1000 LAN
2. HERO11 Black  
3. Thunderbolt Bridge
4. Wi-Fi
5. iPhone USB
6. Tailscale

Select a network service (enter number): 4
```

**Option B - Manual Configuration:**

```bash
# Configure Wi-Fi to use the proxy (adjust network name if different)
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8888 off
sudo networksetup -setwebproxystate "Wi-Fi" on
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8888 off
sudo networksetup -setsecurewebproxystate "Wi-Fi" on
```

### 6. Set Up Real-Time Monitoring

Create a monitoring script to watch FunGame2 traffic in real-time:

```bash
cat > monitor-fungame2.sh << 'EOF'
#!/bin/bash

echo "=== FunGame2 Traffic Monitor ==="
echo "Monitoring all traffic to fungame2.com..."
echo "Press Ctrl+C to stop monitoring"
echo "================================"

# Monitor the log file in real-time, filtering for fungame2.com traffic
tail -f fungame2-traffic.log | grep --line-buffered "fungame2.com"
EOF

chmod +x monitor-fungame2.sh
```

### 7. Start Monitoring and Launch Game

In a new terminal window, start the real-time monitor:

```bash
./monitor-fungame2.sh
```

Now launch FunGame2. You'll immediately see all traffic to fungame2.com displayed in real-time.

## Sample Output

When FunGame2 connects to its servers, you'll see output like:

```
time="2025-08-05 10:30:15.123" level=INFO msg="HTTPS request intercepted" host="api.fungame2.com" method="POST" path="/auth/login"
time="2025-08-05 10:30:15.124" level=INFO msg="Request body" host="api.fungame2.com" body="{\"username\":\"player123\",\"password_hash\":\"abc123...\"}"
time="2025-08-05 10:30:15.456" level=INFO msg="HTTPS response" host="api.fungame2.com" status=200 
time="2025-08-05 10:30:15.457" level=INFO msg="Response body" host="api.fungame2.com" body="{\"token\":\"jwt_token_here\",\"player_id\":12345}"
```

## Advanced Log Analysis

### Filter Specific Request Types

```bash
# View only login/authentication requests
grep -E "login|auth|token" fungame2-traffic.log

# View only POST requests
grep "method=POST" fungame2-traffic.log

# View only API calls
grep "api.fungame2.com" fungame2-traffic.log
```

### Extract JSON Responses

```bash
# Extract all response bodies (requires jq)
grep "Response body" fungame2-traffic.log | sed 's/.*body=//' | jq '.'
```

### Monitor Specific Game Actions

```bash
# Filter for gameplay-related endpoints
tail -f fungame2-traffic.log | grep -E "gameplay|match|score|leaderboard"
```

## Cleanup When Done

### Stop Monitoring and Proxy

1. Stop the real-time monitor: Press `Ctrl+C` in the monitoring terminal
2. Stop the proxy server: Press `Ctrl+C` in the proxy terminal

### Disable System Proxy

**Option A - Automatic:**
```bash
./build/bin/breakthru -disable
```

**Option B - Manual:**
```bash
sudo networksetup -setwebproxystate "Wi-Fi" off
sudo networksetup -setsecurewebproxystate "Wi-Fi" off
```

### Verify Proxy Disabled

```bash
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"
```

Both should show "Enabled: No"

## Troubleshooting

### Game Not Connecting Through Proxy

Some games bypass system proxy settings. If FunGame2 isn't showing traffic:

1. **Check if transparent mode is available:**
   ```bash
   ./build/bin/breakthru -config fungame2-config.json -transparent
   ```

2. **Try different proxy ports:**
   - Update `fungame2-config.json` to use port 8080 or 3128
   - Reconfigure system proxy to match

### Certificate Issues

If you see SSL/TLS errors:

1. **Verify CA certificate installation:**
   ```bash
   security find-certificate -c "breakthru" /Library/Keychains/System.keychain
   ```

2. **Reinstall the certificate:**
   ```bash
   sudo security delete-certificate -c "breakthru" /Library/Keychains/System.keychain
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./certs/ca.crt
   ```

### No Traffic Appearing

1. **Check proxy configuration:**
   ```bash
   networksetup -getwebproxy "Wi-Fi"
   ```

2. **Test proxy with curl:**
   ```bash
   curl -x http://127.0.0.1:8888 http://fungame2.com
   ```

3. **Check if game uses different domains:**
   ```bash
   # Monitor all traffic (not just fungame2.com)
   tail -f fungame2-traffic.log
   ```

## Files Created

After completing this example, you'll have:

- `fungame2-config.json` - Game-specific proxy configuration
- `fungame2-traffic.log` - All captured traffic logs  
- `monitor-fungame2.sh` - Real-time monitoring script
- `certs/ca.crt` - CA certificate (auto-generated)
- `certs/ca.key` - CA private key (auto-generated)

## Security Notes

- The CA certificate allows breakthru to decrypt HTTPS traffic
- Only install the CA certificate on systems you control
- Remove the CA certificate when finished: 
  ```bash
  sudo security delete-certificate -c "breakthru" /Library/Keychains/System.keychain
  ```
- Never share the `certs/ca.key` file - it's your private key

## Next Steps

- Analyze the captured traffic to understand FunGame2's communication patterns
- Look for API endpoints, authentication mechanisms, and data formats
- Use the logged data to understand the game's backend architecture
- Consider filtering logs for specific game features you're investigating