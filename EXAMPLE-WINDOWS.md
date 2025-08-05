# Example: Monitoring Game Traffic for FunGame2 on Windows

This example walks through setting up breakthru to monitor all HTTP/HTTPS traffic between a desktop game (FunGame2) and its servers at fungame2.com on Windows.

## Scenario

- **Game**: FunGame2 (desktop application)
- **Target Domain**: fungame2.com (and all subdomains)
- **Platform**: Windows 10/11 with admin privileges
- **Goal**: Monitor all HTTP/HTTPS requests and responses in real-time

## Prerequisites

- Windows 10/11 with administrator privileges
- Command Prompt or PowerShell comfort level
- Willingness to install a custom CA certificate

## Step-by-Step Setup

### 1. Download or Build the Application

**Option A - Download Pre-built Binary:**
Download `breakthru.exe` from the releases page and place it in a folder like `C:\breakthru\`

**Option B - Build from Source:**
If you have Go installed:

```cmd
make build-local
```

Or manually:
```cmd
go build -o breakthru.exe ./cmd/breakthru
```

### 2. Create Game-Specific Configuration

Open Command Prompt as Administrator and navigate to your breakthru folder:

```cmd
cd C:\breakthru
```

Create a configuration file for monitoring FunGame2:

```cmd
echo {> fungame2-config.json
echo   "port": 8888,>> fungame2-config.json
echo   "log_file": "fungame2-traffic.log",>> fungame2-config.json
echo   "verbose": true,>> fungame2-config.json
echo   "https_interception": true,>> fungame2-config.json
echo   "auto_generate_ca": true,>> fungame2-config.json
echo   "cert_store_dir": "./certs",>> fungame2-config.json
echo   "https_log_bodies": true,>> fungame2-config.json
echo   "https_only_domains": ["fungame2.com", "*.fungame2.com"],>> fungame2-config.json
echo   "buffer_size": 65536,>> fungame2-config.json
echo   "https_max_body_size": 10485760>> fungame2-config.json
echo }>> fungame2-config.json
```

**Alternative - Using PowerShell:**
```powershell
@"
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
"@ | Out-File -FilePath "fungame2-config.json" -Encoding UTF8
```

**Configuration Details:**
- `port: 8888` - Proxy listens on port 8888
- `https_only_domains` - Only intercept HTTPS for fungame2.com domains
- `https_log_bodies: true` - Log full request/response bodies
- `https_max_body_size: 10485760` - Log bodies up to 10MB

### 3. Start the Proxy Server

Launch breakthru with the game configuration:

```cmd
breakthru.exe -config fungame2-config.json
```

Expected output:
```
time="2025-08-05 10:15:59.803" level=INFO msg="Starting breakthru proxy" version=c260eb6-dirty
time="2025-08-05 10:15:59.804" level=INFO msg="CA loaded successfully" cert_path=./certs/ca.crt
time="2025-08-05 10:15:59.805" level=INFO msg="Starting proxy server" port=8888
```

Keep this Command Prompt window open - the proxy server is now running.

### 4. Install the CA Certificate

The proxy automatically generates a CA certificate. Install it in Windows:

**Method 1 - Using breakthru (if supported):**
Open a new Command Prompt as Administrator and run:
```cmd
breakthru.exe -install-cert
```

**Method 2 - Manual Installation:**
1. Open `certlm.msc` (Local Machine Certificate Manager)
2. Navigate to **Trusted Root Certification Authorities** → **Certificates**
3. Right-click in the certificates area
4. Select **All Tasks** → **Import...**
5. Browse to `certs\ca.crt` in your breakthru folder
6. Complete the import wizard

**Method 3 - PowerShell (as Administrator):**
```powershell
Import-Certificate -FilePath ".\certs\ca.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
```

### 5. Configure System Proxy

**Option A - Automatic Configuration (Recommended):**

```cmd
breakthru.exe -enable -port 8888
```

This will automatically configure Windows system proxy settings.

**Option B - Manual Configuration via PowerShell:**

```powershell
# Enable system proxy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8888"

# Refresh Internet Explorer settings
$signature = @'
[DllImport("wininet.dll")]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
$wininet = Add-Type -MemberDefinition $signature -Name Wininet -Namespace InternetSettings -PassThru
[void]$wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
[void]$wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
```

**Option C - Manual Configuration via GUI:**
1. Open **Settings** → **Network & Internet** → **Proxy**
2. Under **Manual proxy setup**, toggle **Use a proxy server** to **On**
3. Set **Address**: `127.0.0.1`
4. Set **Port**: `8888`
5. Click **Save**

### 6. Set Up Real-Time Monitoring

Create a batch file to monitor FunGame2 traffic in real-time:

```cmd
echo @echo off> monitor-fungame2.bat
echo echo === FunGame2 Traffic Monitor ===>> monitor-fungame2.bat
echo echo Monitoring all traffic to fungame2.com...>> monitor-fungame2.bat
echo echo Press Ctrl+C to stop monitoring>> monitor-fungame2.bat
echo echo ================================>> monitor-fungame2.bat
echo.>> monitor-fungame2.bat
echo powershell -Command "Get-Content fungame2-traffic.log -Wait | Where-Object { $_ -match 'fungame2.com' }">> monitor-fungame2.bat
```

**Alternative - PowerShell Script:**
```powershell
@"
Write-Host "=== FunGame2 Traffic Monitor ==="
Write-Host "Monitoring all traffic to fungame2.com..."
Write-Host "Press Ctrl+C to stop monitoring"
Write-Host "================================"

Get-Content fungame2-traffic.log -Wait | Where-Object { `$_ -match "fungame2.com" }
"@ | Out-File -FilePath "monitor-fungame2.ps1" -Encoding UTF8
```

### 7. Start Monitoring and Launch Game

**Using Batch File:**
Open a new Command Prompt window and run:
```cmd
monitor-fungame2.bat
```

**Using PowerShell:**
Open a new PowerShell window and run:
```powershell
.\monitor-fungame2.ps1
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

### Filter Specific Request Types (PowerShell)

```powershell
# View only login/authentication requests
Select-String -Pattern "login|auth|token" -Path "fungame2-traffic.log"

# View only POST requests
Select-String -Pattern "method=POST" -Path "fungame2-traffic.log"

# View only API calls
Select-String -Pattern "api.fungame2.com" -Path "fungame2-traffic.log"
```

### Filter Specific Request Types (Command Prompt with findstr)

```cmd
# View only login/authentication requests
findstr /i "login auth token" fungame2-traffic.log

# View only POST requests
findstr "method=POST" fungame2-traffic.log

# View only API calls
findstr "api.fungame2.com" fungame2-traffic.log
```

### Extract JSON Responses

**PowerShell (if you have jq for Windows):**
```powershell
Select-String -Pattern "Response body" -Path "fungame2-traffic.log" | ForEach-Object { ($_ -split "body=")[1] } | jq .
```

### Monitor Specific Game Actions

**Real-time filtering:**
```powershell
Get-Content fungame2-traffic.log -Wait | Where-Object { $_ -match "gameplay|match|score|leaderboard" }
```

## Cleanup When Done

### Stop Monitoring and Proxy

1. Stop the real-time monitor: Press `Ctrl+C` in the monitoring window
2. Stop the proxy server: Press `Ctrl+C` in the proxy window

### Disable System Proxy

**Option A - Automatic:**
```cmd
breakthru.exe -disable
```

**Option B - Manual via PowerShell:**
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0

# Refresh settings
$signature = @'
[DllImport("wininet.dll")]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
$wininet = Add-Type -MemberDefinition $signature -Name Wininet -Namespace InternetSettings -PassThru
[void]$wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
[void]$wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
```

**Option C - Manual via GUI:**
1. Open **Settings** → **Network & Internet** → **Proxy**
2. Under **Manual proxy setup**, toggle **Use a proxy server** to **Off**

### Verify Proxy Disabled

**PowerShell:**
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable
```

Should return `ProxyEnable : 0`

## Troubleshooting

### Game Not Connecting Through Proxy

Some games bypass system proxy settings. If FunGame2 isn't showing traffic:

1. **Check Windows Firewall:**
   ```cmd
   netsh advfirewall firewall add rule name="breakthru" dir=in action=allow protocol=TCP localport=8888
   ```

2. **Try transparent mode (if available):**
   ```cmd
   breakthru.exe -config fungame2-config.json -transparent
   ```

3. **Use different proxy ports:**
   - Update `fungame2-config.json` to use port 8080 or 3128
   - Reconfigure system proxy to match

### Certificate Issues

If you see SSL/TLS errors:

1. **Verify CA certificate installation:**
   ```powershell
   Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Subject -match "breakthru" }
   ```

2. **Reinstall the certificate:**
   ```powershell
   # Remove old certificate
   Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Subject -match "breakthru" } | Remove-Item
   
   # Install new certificate
   Import-Certificate -FilePath ".\certs\ca.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
   ```

### Permission Issues

If you get "Access Denied" errors:

1. **Run Command Prompt as Administrator**
2. **Check Windows UAC settings**
3. **Temporarily disable antivirus** (some antivirus software blocks proxy tools)

### No Traffic Appearing

1. **Check proxy configuration:**
   ```powershell
   Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
   ```

2. **Test proxy with curl (if installed):**
   ```cmd
   curl -x http://127.0.0.1:8888 http://fungame2.com
   ```

3. **Check Windows Event Viewer:**
   - Open Event Viewer
   - Check Application and System logs for breakthru-related errors

4. **Check if game uses different domains:**
   ```cmd
   # Monitor all traffic (not just fungame2.com)
   type fungame2-traffic.log
   ```

### Antivirus Interference

Some antivirus software may flag breakthru or block its network access:

1. **Add breakthru.exe to antivirus exclusions**
2. **Temporarily disable real-time protection** for testing
3. **Check Windows Defender exclusions:**
   ```powershell
   Add-MpPreference -ExclusionProcess "breakthru.exe"
   Add-MpPreference -ExclusionPath "C:\breakthru"
   ```

## Files Created

After completing this example, you'll have:

- `fungame2-config.json` - Game-specific proxy configuration
- `fungame2-traffic.log` - All captured traffic logs  
- `monitor-fungame2.bat` - Real-time monitoring batch script
- `monitor-fungame2.ps1` - Real-time monitoring PowerShell script
- `certs\ca.crt` - CA certificate (auto-generated)
- `certs\ca.key` - CA private key (auto-generated)

## Security Notes

- The CA certificate allows breakthru to decrypt HTTPS traffic
- Only install the CA certificate on systems you control
- Remove the CA certificate when finished:
  ```powershell
  Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Subject -match "breakthru" } | Remove-Item
  ```
- Never share the `certs\ca.key` file - it's your private key
- Some corporate networks may block or detect this type of traffic analysis

## Windows-Specific Considerations

- **Windows Firewall**: May need to allow breakthru through firewall
- **UAC (User Account Control)**: Some operations require Administrator privileges
- **Antivirus Software**: May interfere with proxy operations
- **Corporate Policies**: Group Policy may prevent proxy configuration changes
- **Windows Store Apps**: May not respect system proxy settings (use traditional desktop apps for better results)

## Next Steps

- Analyze the captured traffic to understand FunGame2's communication patterns
- Look for API endpoints, authentication mechanisms, and data formats
- Use the logged data to understand the game's backend architecture
- Consider filtering logs for specific game features you're investigating
- Set up automated log rotation for long-term monitoring sessions