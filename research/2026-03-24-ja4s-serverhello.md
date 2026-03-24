# Research: Go crypto/tls ServerHello Fingerprint (JA4S)
Date: 2026-03-24
Stage: 5.2 (Issue #7)
Query: Go ServerHello fingerprint, JA4S detection risk, mitigation options

## Summary
Go's TLS 1.3 ServerHello produces JA4S approximately
`t1302h2_1301_a56c5b993250` — 2 extensions (supported_versions +
key_share), AES-128-GCM cipher, ALPN=h2. This is identical to
Caddy's JA4S since Caddy uses the same Go crypto/tls stack.
In TLS 1.3, most servers (Go, OpenSSL-based) converge to very
similar JA4S values.

## Key Findings
- Go's ServerHello extension order is hardcoded in serialization
  code and cannot be changed via tls.Config
- TLS 1.3 cipher suite selection is not configurable in Go
- JA4S is response-dependent (varies by ClientHello), making it
  a weak standalone detection vector
- TSPU primarily uses client-side fingerprinting (JA3/JA4)
- JA4S is gaining adoption in NDR/SOC tools (Zeek, Arkime, Censys)
  but as a supplementary signal, not primary detector
- Ghost's JA4S is indistinguishable from Caddy's (same TLS stack)

## Impact on Implementation
Issue #7 is assessed as P3 (low priority). Ghost's server-side
TLS fingerprint does not stand out because:
1. It matches Caddy (a legitimate, widely-used web server)
2. TSPU does not appear to use JA4S as a primary detection vector
3. The fallback to Caddy makes the "Go server" appearance expected

No code changes needed. If JA4S becomes a detection vector in
the future, the mitigation would be to place an actual Nginx/Caddy
in front of Ghost for TLS termination.

## Decision
Close Issue #7 as P3 — "not a real risk with current TSPU capabilities."
Document as accepted risk.

## Sources
- FoxIO JA4+ specification
- Go crypto/tls source (serverHelloMsg.marshal)
- TSPU detection research 2024-2026
- Zeek JA4 package documentation
