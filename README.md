# Ghost Protocol

`Ghost` is a stealth transport / VPN protocol that carries traffic through Chrome-like TLS 1.3 and HTTP/2 sessions. The repository contains the Go client/server implementation, Linux TUN and SOCKS5 modes, Android VPN work, traffic shaping profiles, deployment material, and research notes behind the transport decisions.

## Highlights

- Chrome-like TLS fingerprinting via uTLS/fhttp (JA3/JA4, Akamai HTTP/2 settings, ALPS)
- Multiplexed binary framing over long-lived HTTP/2 request/response streams
- Traffic shaping profiles built from empirical Chrome capture data
- Multiple operating modes: performance, balanced, and stealth
- Client-side SOCKS5 proxy and Linux TUN support
- Android VPN client based on `VpnService`
- Caddy fallback for non-Ghost traffic / active probing resistance
- Automatic reconnect and operational deployment tooling

## Repository map

- `cmd/ghost-server` — server entrypoint
- `cmd/ghost-client` — desktop/Linux client entrypoint
- `cmd/ghost-keygen` — key generation utility
- `internal/` — transport, mux, framing, proxy, shaping, auth, config
- `android/` — Android app project
- `mobile/` — gomobile-facing bindings, Android glue code, and local AAR build tooling
- `configs/` — example configuration files
- `deploy/` — deployment scripts and environment helpers
- `docs/` — operator-facing documentation
- `release/` — release templates, sample configs, and packaging material (generated binaries stay out of git)
- `research/` — research notes, measurements, and protocol experiments
- `tools/` — profiling / analysis / stress helpers

## Quick start

```bash
# 1. Generate keys
go run ./cmd/ghost-keygen

# 2. Build server and client
go build -o ghost-server ./cmd/ghost-server
go build -o ghost-client ./cmd/ghost-client

# 3. Prepare configs
cp configs/server.example.yaml /etc/ghost/server.yaml
cp configs/client.yaml ./client.yaml

# 4. Run
ghost-server -config /etc/ghost/server.yaml
ghost-client -config ./client.yaml
```

For a full server setup, certificate flow, and reverse-proxy layout, start with [docs/DEPLOY.md](docs/DEPLOY.md). Client-side usage and operating modes are covered in [docs/CLIENT.md](docs/CLIENT.md).

## Architecture at a glance

```text
Client app / browser
        ↓
  SOCKS5 or TUN
        ↓
 stream mux + framing
        ↓
Chrome-like TLS 1.3 + HTTP/2
        ↓
server transport gate
        ├─ Ghost traffic → mux → target upstream
        └─ non-Ghost traffic → Caddy fallback site
```

The protocol is built around looking like a real browser transport session first and a tunnel second. Fingerprint selection, HTTP/2 settings, packet sizing, and timing behavior are all treated as protocol surface, not afterthoughts.

## Documentation

- [Deployment guide](docs/DEPLOY.md)
- [Client guide](docs/CLIENT.md)
- [Security notes](docs/SECURITY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Research and artifacts

The repo keeps the engineering path visible:

- `research/` contains protocol notes, validation writeups, and performance investigations
- `release/` contains packaged outputs for Linux, Windows, Android, and server deployment
- `docs/diagnostics/` contains archived raw VPS diagnostic logs that are useful historically, but should not clutter the repository root

## Current status

This is an actively developed systems repo, not a toy proof-of-concept. The transport, shaping, deployment, and Android work all live in one place, with accompanying docs and research notes. Some platform-specific tests (especially mobile / VPN-related ones) may require environment-specific support beyond a plain Linux shell.
