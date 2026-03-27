# Ghost

Stealth VPN protocol that tunnels traffic through Chrome-identical TLS/HTTP2 connections to bypass deep packet inspection.

## Features

- **Chrome-identical TLS fingerprint** — JA4/JA3, Akamai h2 SETTINGS, ALPS via uTLS
- **HTTP/2 multiplexed tunnel** — binary framing over real HTTP/2 POST/GET streams
- **Traffic shaping** — padding, timing jitter, and cover traffic from empirical Chrome profiles
- **Three modes** — Performance (78 Mbps), Balanced (58 Mbps), Stealth (full shaping)
- **SOCKS5 proxy** — local proxy for browser/app configuration
- **TUN mode** — route all traffic on Linux (via netstack)
- **Android VPN client** — native app with VpnService integration
- **Caddy fallback** — non-Ghost connections see a real website (defeats active probing)
- **Auto-reconnection** — detects connection freezes and reconnects transparently
- **Let's Encrypt certificates** — automatic TLS via ACME, zero manual cert management

## Quick Start

```bash
# 1. Generate keys
go run ./cmd/ghost-keygen

# 2. Build
go build -o ghost-server ./cmd/ghost-server
go build -o ghost-client ./cmd/ghost-client

# 3. Deploy server (copy binary + config to VPS)
scp ghost-server configs/server.example.yaml user@YOUR_SERVER_IP:/etc/ghost/

# 4. Connect
ghost-client -config configs/client.yaml
```

Copy the keygen output into `server.yaml` and `client.yaml` as indicated. See [docs/DEPLOY.md](docs/DEPLOY.md) and [docs/CLIENT.md](docs/CLIENT.md) for full setup.

## Architecture

```
Client                                              Server
┌──────────────────────────┐     TLS 1.3    ┌──────────────────────────┐
│ App/Browser              │    (Chrome FP)  │ TLS Termination          │
│   ↓                      │                 │   ↓ ClientHello check    │
│ SOCKS5 / TUN             │                 │   ├─ Ghost → Mux/Framing │
│   ↓                      │    HTTP/2       │   └─ Other → Caddy (web) │
│ Mux (streams)            │  ◄═══════════►  │ Mux (streams)            │
│   ↓                      │                 │   ↓                      │
│ Framing (bin protocol)   │                 │ Framing                  │
│   ↓                      │                 │   ↓                      │
│ Shaping (pad/time/cover) │                 │ Destination (internet)   │
│   ↓                      │                 │                          │
│ HTTP/2 + uTLS            │                 │                          │
└──────────────────────────┘                 └──────────────────────────┘
```

## Performance

| Mode        | Throughput | Shaping          | Use Case                     |
|-------------|------------|------------------|------------------------------|
| Performance | ~78 Mbps   | Minimal padding  | No active DPI                |
| Balanced    | ~58 Mbps   | Moderate shaping | Default, everyday use        |
| Stealth     | ~58 Mbps   | Full shaping     | Under active TSPU/DPI        |

## Building

Requires Go 1.22+.

```bash
go build -o ghost-server ./cmd/ghost-server
go build -o ghost-client ./cmd/ghost-client
go build -o ghost-keygen ./cmd/ghost-keygen
```

Cross-compile for Linux server:
```bash
GOOS=linux GOARCH=amd64 go build -o ghost-server-linux ./cmd/ghost-server
```

## Project Structure

```
cmd/ghost-server/     Server entrypoint (systemd-notify, ACME, session mgmt)
cmd/ghost-client/     Client entrypoint (SOCKS5, TUN, reconnection)
cmd/ghost-keygen/     Key pair generator (x25519)
internal/auth/        Key exchange, session ID injection, token verification
internal/transport/   uTLS dialer, HTTP/2 config, TLS server with fallback
internal/framing/     Binary frame protocol (data, open, close, padding, keepalive)
internal/mux/         Stream multiplexer over framing layer
internal/proxy/       SOCKS5 server (RFC 1928)
internal/shaping/     Traffic shaping: padding, timing, cover traffic, profiles
internal/config/      YAML config parsing and validation
mobile/               gomobile bindings for Android (VpnService + netstack)
android/              Android app (Jetpack Compose, Material 3)
configs/              Example YAML configs for server and client
deploy/               systemd unit, nftables, Caddyfile, sysctl, install script
profiles/             Traffic shaping profiles (Chrome browsing)
tools/                Benchmarks, stress tests, traffic analysis utilities
```

## Documentation

- [docs/DEPLOY.md](docs/DEPLOY.md) — Server deployment guide
- [docs/CLIENT.md](docs/CLIENT.md) — Client setup (Linux, Windows, Android)
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — Common issues and fixes
- [docs/SECURITY.md](docs/SECURITY.md) — Security model and threat analysis
