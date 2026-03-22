# fhttp + uTLS Integration Evaluation

**Date:** 2026-03-22
**Libraries evaluated:**
- `github.com/bogdanfinn/fhttp` v0.6.8
- `github.com/refraction-networking/utls` v1.8.2
- `github.com/bogdanfinn/utls` v1.7.7-barnius (transitive dep of fhttp)

## Chosen Libraries

**TLS:** `refraction-networking/utls` v1.8.2 — the upstream uTLS library.
Provides `HelloChrome_Auto` preset which auto-selects the latest Chrome
ClientHello fingerprint (currently Chrome 131+, including GREASE, ECH,
X25519MLKEM768 post-quantum key exchange).

**HTTP/2:** `bogdanfinn/fhttp` v0.6.8 — fork of Go's net/http with
configurable HTTP/2 fingerprinting (SETTINGS order, pseudo-header order,
connection flow control, stream priorities).

## How Integration Works

The integration uses `fhttp/http2.Transport` directly (NOT `fhttp.Transport`)
because fhttp's main Transport type-asserts TLS connections to
`*bogdanfinn/utls.Conn`, which is incompatible with
`*refraction-networking/utls.UConn`.

### Architecture

```
refraction-networking/utls   ──→  TLS handshake (Chrome fingerprint)
                                   │
                                   ▼
                              net.Conn (utls.UConn)
                                   │
bogdanfinn/fhttp/http2       ──→  HTTP/2 framing (Chrome SETTINGS)
                                   │
                                   ▼
                              fhttp.Client ──→ HTTP requests
```

### Key Code Pattern

```go
h2Transport := &http2.Transport{
    DialTLS: func(network, addr string, _ *btls.Config) (net.Conn, error) {
        // Use refraction-networking/utls for TLS, return net.Conn
        rawConn, _ := net.Dial(network, addr)
        uconn := utls.UClient(rawConn, &utls.Config{ServerName: host},
            utls.HelloChrome_Auto)
        uconn.Handshake()
        return uconn, nil  // utls.UConn implements net.Conn
    },
    Settings: map[http2.SettingID]uint32{ ... },
    SettingsOrder: []http2.SettingID{ ... },
    ConnectionFlow: 15663105,
    PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
}
client := &http.Client{Transport: h2Transport}
```

### Why `http2.Transport` Instead of `fhttp.Transport`

`fhttp.Transport` + `DialTLSContext` + `ForceAttemptHTTP2=true` does NOT work
with `refraction-networking/utls` because:

1. fhttp's transport checks `pconn.conn.(*tls.Conn)` — explicit type assertion
   to `*bogdanfinn/utls.Conn`
2. `refraction-networking/utls.UConn` is a different type, assertion fails
3. fhttp falls back to HTTP/1.1

Using `http2.Transport` directly works because:
1. `DialTLS` returns `net.Conn` — any conn implementing the interface works
2. `http2.Transport` handles HTTP/2 framing on top without TLS type checks
3. Full control over SETTINGS, pseudo-header order, connection flow

## Verified Fingerprint Results

### TLS (from tls.peet.ws)
- **JA4:** `t13d1516h2_8daaf6152771_d8a2da3f94cd`
- **JA3 MD5:** `8673f7b121673985730121d9f633889d`
- **TLS version:** 1.3 (0x0304)
- **ALPN:** h2
- Includes: GREASE, ECH, X25519MLKEM768 (post-quantum), brotli cert compression

### HTTP/2 (from tls.peet.ws)
- **Akamai fingerprint:** `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
- **SETTINGS:** HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
  INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144
- **WINDOW_UPDATE:** 15663105
- **Pseudo-header order:** :method, :authority, :scheme, :path (m,a,s,p)

All values match real Chrome 131 behavior.

## Limitations and Issues

1. **Two utls packages required:** `bogdanfinn/utls` must be imported solely
   for the `DialTLS` function signature type compatibility (`*btls.Config`
   parameter). Only `refraction-networking/utls` is used for actual TLS.

2. **No automatic HTTP/2 upgrade:** Cannot use `fhttp.Transport` with
   `ForceAttemptHTTP2` for our use case — must use `http2.Transport` directly.
   This means connection pooling and HTTP/1.1 fallback must be handled manually.

3. **Connection reuse:** `http2.Transport` manages connection pooling internally
   but each new host requires a new TLS connection through `DialTLS`.

4. **Stream priorities:** fhttp supports `Priorities` field on `http2.Transport`
   for stream prioritization (Chrome uses EXCLUSIVE bit, weight 256). Not yet
   configured but available when needed.

## Server-Side HTTP/2 Support (Phase 2.2 Note)

`bogdanfinn/fhttp` is a **client-focused** fork. It does NOT include server-side
HTTP/2 support. For the Ghost server's HTTP/2 handler, options include:

1. **Go stdlib `net/http` + `x/net/http2`** — standard server-side HTTP/2, but
   no fingerprint customization (not needed for server side)
2. **Direct frame handling** — use `x/net/http2/hpack` for HPACK encoding with
   a custom frame writer on top of the TLS connection
3. **For camouflage:** The server needs to respond with Chrome-like server
   SETTINGS. This can be done with `x/net/http2` server configuration or by
   wrapping the connection with a custom HTTP/2 server implementation.

Recommendation: Use Go stdlib `net/http` server with custom `http2.Server`
configuration for server-side. The server's HTTP/2 fingerprint is less critical
since DPI focuses on client fingerprints.
