# Security Model

## Threat Model

Ghost is designed to defeat Russia's TSPU (Technical System for Countering Threats) — a nationwide DPI system deployed at ISP level. TSPU uses multiple detection layers:

| TSPU Layer             | Detection Method                        | Ghost Countermeasure                              |
|------------------------|-----------------------------------------|---------------------------------------------------|
| TLS fingerprinting     | JA3/JA4 hash of ClientHello             | Chrome-identical fingerprint via uTLS             |
| HTTP/2 fingerprinting  | SETTINGS, WINDOW_UPDATE, header order   | Chrome 146 SETTINGS, pseudo-header order, ALPS    |
| Active probing         | Connect to server, check if it's a proxy| Caddy fallback serves real website                |
| Traffic analysis       | Packet size/timing patterns             | Padding, timing jitter, cover traffic profiles    |
| Connection freezing    | Silently drop packets on suspect flows  | Freeze detection + automatic reconnection         |
| SNI/domain filtering   | Block known VPN domains                 | Use innocuous domain with real website behind it  |
| IP reputation          | Block known datacenter IP ranges        | Use residential-looking VPS or rotate IPs         |

## What Ghost Protects Against

- **TLS fingerprinting** — uTLS generates a ClientHello byte-identical to Chrome 146, including extensions order, supported curves, and signature algorithms. JA4 and Akamai h2 fingerprints match real Chrome.
- **HTTP/2 fingerprinting** — SETTINGS frame values, WINDOW_UPDATE sizes, pseudo-header order, and ALPS settings all match Chrome 146.
- **Active probing** — Non-Ghost connections (including manual `curl`, scanners, censors) receive a real website from Caddy. The server is indistinguishable from a legitimate HTTPS site.
- **Traffic analysis** — Three shaping modes use empirical distributions captured from real Chrome browsing sessions. Padding, inter-packet timing, and burst patterns match observed Chrome behavior.
- **Connection freezing** — Health checks detect when a connection stops passing data. Client automatically reconnects with a new TLS session.

## What Ghost Does NOT Protect Against

- **Endpoint compromise** — If your device is seized or has malware, Ghost cannot help. Keys stored on disk are readable by anyone with device access.
- **Targeted surveillance** — An adversary with full packet capture at both ends can correlate traffic by timing and volume, regardless of shaping.
- **UDP traffic** — Ghost tunnels TCP only. UDP (DNS, QUIC, gaming) is not supported. DNS in TUN mode is resolved via TCP to the configured DNS server.
- **IPv6** — Currently not tunneled. IPv6 traffic bypasses Ghost entirely. Disable IPv6 on the client if this is a concern.
- **Datacenter IP reputation** — VPS IP addresses may be flagged by IP reputation databases regardless of how the protocol behaves. If your VPS IP range is blocked, switch providers.
- **Protocol timing at scale** — A single user's traffic is shaped to match Chrome. Multiple concurrent users from the same IP create patterns that don't match single-browser behavior.

## Cryptographic Design

### Key Exchange

- **Algorithm:** x25519 (Curve25519 Diffie-Hellman)
- **Key size:** 32 bytes (256-bit)
- **Implementation:** `golang.org/x/crypto/curve25519`
- **Shared secret:** Derived from client private key + server public key (or vice versa). Validated against all-zeros (low-order point rejection).

### Authentication Flow

1. **Key generation:** `ghost-keygen` produces two x25519 key pairs (server + client)
2. **Session ID injection:** Client computes `HMAC-SHA256(shared_secret, ClientHello.Random)` and injects the first 32 bytes into the TLS ClientHello SessionID field
3. **Server verification:** Server parses ClientHello, extracts Random and SessionID, recomputes the HMAC with each precomputed shared secret. Uses constant-time comparison. Iterates all secrets even after a match to prevent timing side-channels.
4. **Session token:** After TLS handshake completes, client derives `HMAC-SHA256(shared_secret, "ghost-session" || tls_binding)` where `tls_binding` is TLS exported keying material (RFC 5705). Sent as `X-Session-Token` header.
5. **Token verification:** Server verifies the token with the same derivation using the matched shared secret.

### What This Achieves

- Ghost traffic is authenticated at the TLS layer (SessionID) before any HTTP data is exchanged
- Non-Ghost connections are routed to Caddy immediately, without revealing Ghost exists
- The authentication is invisible to network observers — SessionID looks like a normal TLS session resumption attempt
- TLS binding prevents token replay across different TLS sessions

## Key Management

### Generation

```bash
go run ./cmd/ghost-keygen
```

Produces two key pairs. The output tells you which keys go in which config file.

### Storage

- **Server:** Keys live in `/etc/ghost/server.yaml`, readable only by the `ghost` user
- **Client:** Keys live in the client config file on your device
- **Android:** Keys are stored in encrypted SharedPreferences (`androidx.security:security-crypto`)
- **Never** commit private keys to git

### Rotation

1. Run `ghost-keygen` to generate new key pairs
2. Update server config with new keys, restart server
3. Update all client configs with new keys
4. Old connections will fail authentication — clients must reconnect with new keys

### If Keys Are Compromised

An attacker with both the client private key and server public key can:
- Authenticate to your server as a legitimate client
- Derive the shared secret and potentially forge session tokens

Response:
1. Generate new keys immediately
2. Update server and all client configs
3. Restart the server (drops existing sessions)
4. If keys were ever in git history: use `git filter-repo` to purge them

## Server Hardening

Ghost's deployment includes several hardening measures:

- **Non-root execution:** Runs as `ghost` system user with no login shell
- **CAP_NET_BIND_SERVICE:** Only capability granted — allows binding port 443 without root
- **NoNewPrivileges:** Process cannot gain additional privileges
- **Filesystem isolation:** `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true` — only `/etc/ghost`, `/var/lib/ghost`, `/var/log/ghost` are writable
- **nftables firewall:** Default-drop policy, only ports 22/80/443 allowed inbound
- **Kernel tuning:** TCP buffer optimization, TCP Fast Open enabled

## Known Limitations

- **Single server** — No failover or load balancing. If the VPS goes down, all users lose connectivity.
- **No forward secrecy for tunnel data** — Session keys are derived from static x25519 keys. If keys are compromised, past recorded traffic could theoretically be decrypted (requires also having captured the TLS session keys).
- **No certificate pinning** — Client trusts the TLS certificate presented by the server (validated against system CA store or Let's Encrypt). A CA-level compromise could enable MITM.
- **2-5 user design** — Not tested for scale. Session management, shaping CPU overhead, and bandwidth sharing are designed for a small group.
- **No audit log** — Server logs connection events but doesn't maintain a persistent audit trail of session activity.
- **Go runtime fingerprinting** — While TLS and HTTP/2 are Chrome-identical, the Go runtime's TCP stack behavior (window scaling, timestamps) may differ from Chrome. This is a potential future detection vector.
