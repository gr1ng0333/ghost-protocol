# Client Setup

## Building

Requires Go 1.22+.

```bash
# Linux / macOS
go build -o ghost-client ./cmd/ghost-client

# Windows
go build -o ghost-client.exe ./cmd/ghost-client

# Key generator (needed once)
go build -o ghost-keygen ./cmd/ghost-keygen
```

## Configuration

Create `client.yaml` from the example:

```bash
cp configs/client.example.yaml configs/client.yaml
```

Full configuration with comments:

```yaml
server:
  # Server domain and port
  addr: "YOUR_DOMAIN:443"
  # TLS SNI (must match the domain on the server's certificate)
  sni: "YOUR_DOMAIN"

auth:
  # Paste from ghost-keygen output (client section)
  server_public_key: "<server_public_key_hex>"
  client_private_key: "<client_private_key_hex>"

proxy:
  # "socks5" or "tun" (tun is Linux only)
  mode: "socks5"
  # Local SOCKS5 listen address
  socks5: "127.0.0.1:1080"
  # TUN interface name (Linux tun mode only)
  tun_name: "ghost0"
  # DNS server for TUN mode
  dns: "1.1.1.1:53"

shaping:
  # "stealth", "balanced", or "performance"
  default_mode: "balanced"
  # Path to traffic profile (Chrome browsing patterns)
  profile_path: "profiles/chrome_browsing.json"
  # Allow automatic mode switching based on conditions
  auto_mode: true

log:
  level: "info"
  file: "stdout"
```

## Linux

### SOCKS5 Mode

```bash
./ghost-client -config configs/client.yaml
```

Configure your browser to use SOCKS5 proxy at `127.0.0.1:1080`, or set the environment:

```bash
export ALL_PROXY=socks5://127.0.0.1:1080
```

### TUN Mode

Routes all system traffic through Ghost. Requires root or `CAP_NET_ADMIN`.

Set `proxy.mode: "tun"` in your config, then:

```bash
sudo ./ghost-client -config configs/client.yaml
```

This creates a `ghost0` network interface and routes traffic through it. DNS is resolved via the configured DNS server (default `1.1.1.1:53`).

## Windows

### SOCKS5 Mode

Build and run:

```powershell
go build -o ghost-client.exe ./cmd/ghost-client
.\ghost-client.exe -config configs\client.yaml
```

Configure browser proxy settings to use SOCKS5 at `127.0.0.1:1080`.

**Firefox:** Settings → Network Settings → Manual proxy → SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5.

**Chrome:** Use a proxy extension (e.g., SwitchyOmega) or launch with:
```powershell
chrome.exe --proxy-server="socks5://127.0.0.1:1080"
```

**System-wide:** Settings → Network & Internet → Proxy → Manual setup is for HTTP proxies only. Use per-app configuration or a SOCKS wrapper like `proxifier`.

> **Note:** TUN mode is not supported on Windows.

## Android

### Prerequisites

- Go 1.22+
- [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile): `go install golang.org/x/mobile/cmd/gomobile@latest`
- Android NDK (install via Android Studio → SDK Manager → SDK Tools → NDK)
- `ANDROID_HOME` environment variable set to Android SDK path

Initialize gomobile (once):

```bash
gomobile init
```

### Build AAR

```bash
cd mobile
./build.sh
```

Produces `mobile/ghost.aar` — the Go library compiled for Android.

### Build APK

Copy the AAR into the Android project:

```bash
cp mobile/ghost.aar android/app/libs/
```

Build the app:

```bash
cd android
./gradlew assembleDebug
```

Output: `android/app/build/outputs/apk/debug/app-debug.apk`

### Install & Configure

```bash
adb install android/app/build/outputs/apk/debug/app-debug.apk
```

In the app:
1. Open **Settings**
2. Enter server address: `YOUR_DOMAIN:443`
3. Enter server public key: `<server_public_key_hex>`
4. Enter client private key: `<client_private_key_hex>`
5. Select shaping mode (Balanced recommended)
6. Tap **Connect**

Grant VPN permission when prompted. Disable battery optimization for Ghost to prevent disconnects on screen off.

### Android Tips

- Enable **Always-on VPN** in Android Settings → Network → VPN → Ghost → gear icon
- The app embeds the Chrome browsing profile, so no profile file is needed
- Stats (bytes sent/recv, active streams, uptime) are available in the app UI
- Mode can be changed while connected via `SetMode("stealth")`

## Mode Selection

| Mode        | Description                                        | When to Use                        |
|-------------|----------------------------------------------------|------------------------------------|
| Performance | Minimal padding, no timing constraints. ~78 Mbps.  | No active DPI / trusted network    |
| Balanced    | Moderate padding and timing. ~58 Mbps.             | Default for everyday use           |
| Stealth     | Full padding + timing + cover traffic. ~58 Mbps.   | Under active TSPU / DPI detection  |

**Auto mode** (`auto_mode: true`): Client dynamically switches between modes based on observed conditions. Recommended for production use where DPI activity varies.

Pre-configured client configs are available:
- `configs/client-perf.yaml` — Performance mode, fixed
- `configs/client-balanced.yaml` — Balanced mode, fixed
- `configs/client-stealth.yaml` — Stealth mode, fixed
- `configs/client-production.yaml` — Auto mode (adaptive)
