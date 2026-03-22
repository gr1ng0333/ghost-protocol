# Research: uTLS SessionID Injection with Chrome Preset
Date: 2026-03-22
Stage: 2.3b (Authentication)
Query: How to inject custom SessionID into uTLS ClientHello while preserving Chrome fingerprint

## Summary
uTLS v1.8.2 allows direct modification of ClientHello.SessionId after calling
BuildHandshakeState(). The field is public and writable. The VLESS Reality project
uses the same approach: modify Hello.SessionId and patch Hello.Raw at offset 39.
SessionID is not part of JA4 computation, so the Chrome fingerprint is preserved.

## Key Findings
- No SetSessionID() method exists in uTLS; use direct field assignment on
  HandshakeState.Hello.SessionId
- After BuildHandshakeState(), all fields except session ticket/PSK extensions
  can be modified before Handshake()
- Must also patch Hello.Raw[39:] with the new SessionID bytes (offset 39 =
  type(1) + length(3) + version(2) + random(32) + sid_len(1))
- SessionID is NOT part of JA4 hash computation — changing it preserves fingerprint
- VLESS Reality (Xray-core) uses identical pattern: BuildHandshakeState → set
  Hello.SessionId → copy to Hello.Raw[39:] → Handshake()

## Impact on Implementation
Resolved Issue #13. Ghost uses HelloChrome_Auto (no need for HelloCustom).
SessionID injection works with the standard Chrome preset.

## Sources
- uTLS source: HandshakeState.Hello.SessionId field (u_conn.go)
- uTLS docs: BuildHandshakeState() allows field modification
- Xray-core: transport/internet/reality/reality.go — REALITY SessionID injection
- JA4 specification: SessionID not included in fingerprint computation
