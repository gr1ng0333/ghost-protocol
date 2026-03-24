# Ghost Mobile (Android)

This package provides the gomobile-compatible Go API that is compiled
into an Android AAR via `gomobile bind`. The Kotlin/Java side calls
these exported functions to manage the Ghost VPN tunnel.

## Prerequisites

- Go 1.22+
- Android SDK with NDK installed (`ANDROID_HOME` set)
- gomobile: `go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init`

## Building the AAR

```bash
cd mobile
chmod +x build.sh
./build.sh
```

This produces `ghost.aar` and `ghost-sources.jar` in the `mobile/`
directory. Add both to your Android project's `libs/` folder.

## API

### Kotlin Usage

```kotlin
import ghost.Ghost

// Optional: receive log messages
Ghost.setLogCallback(object : Ghost.LogCallback {
    override fun log(level: String, message: String) {
        Log.d("Ghost", "[$level] $message")
    }
})

// Start VPN — fd from VpnService.establish().detachFd()
val config = """
{
    "server_addr": "203.0.113.42:443",
    "server_sni": "example.com",
    "server_public_key": "hex-encoded-32-bytes",
    "client_private_key": "hex-encoded-32-bytes",
    "shaping_mode": "balanced",
    "auto_mode": true,
    "log_level": "info"
}
"""
val client = Ghost.start(fd.toLong(), config)

// Check health
val healthy = client.healthy()

// Get stats as JSON
val stats = client.stats()

// Change shaping mode
client.setMode("stealth")

// Stop
client.stop()
```

### Config Fields

| Field                | Type    | Required | Description                              |
|----------------------|---------|----------|------------------------------------------|
| `server_addr`        | string  | yes      | Server address as `host:port`            |
| `server_sni`         | string  | yes      | TLS SNI hostname                         |
| `server_public_key`  | string  | yes      | 32-byte hex-encoded server public key    |
| `client_private_key` | string  | yes      | 32-byte hex-encoded client private key   |
| `shaping_mode`       | string  | no       | `"stealth"`, `"balanced"`, `"performance"` (default: `"balanced"`) |
| `auto_mode`          | bool    | no       | Enable adaptive mode switching (default: false) |
| `log_level`          | string  | no       | `"debug"`, `"info"`, `"warn"`, `"error"` (default: `"info"`) |

## Testing

```bash
# From the project root:
go test ./mobile/... -v
```

Note: The gVisor netstack code is Linux-only. Tests run on all platforms
but `Start()` will return an error on non-Linux systems since the TUN
fd setup requires the Linux kernel.

## Architecture

- `ghost.go` — Exported API: `Start`, `Stop`, `Healthy`, `Stats`, `SetMode`, `SetLogCallback`
- `netstack_linux.go` — gVisor netstack setup (Linux/Android)
- `netstack_other.go` — Stub for non-Linux platforms
