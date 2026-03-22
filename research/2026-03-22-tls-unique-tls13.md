# Research: tls_unique Channel Binding in TLS 1.3
Date: 2026-03-22
Stage: 2.3b (Authentication)
Query: tls_unique availability in Go TLS 1.3 and alternatives

## Summary
Go's tls.ConnectionState.TLSUnique returns nil for TLS 1.3 connections
(documented behavior). The replacement is ExportKeyingMaterial(), which
implements RFC 5705/8446 exporters. Both Go stdlib and uTLS v1.8.2 support
ExportKeyingMaterial for TLS 1.3.

## Key Findings
- TLSUnique is nil for TLS 1.3 (RFC 8446 deprecated tls-unique)
- ExportKeyingMaterial(label, context, length) works in Go 1.22+ for TLS 1.3
- uTLS v1.8.2 exposes ExportKeyingMaterial via ConnectionState (inherited from embedded *tls.Conn)
- RFC 9266 defines "tls-exporter" channel binding type for TLS 1.3
- VLESS Reality does NOT use tls_unique or exporters; it derives its own AuthKey
  via ECDH with TLS 1.3 key share + HKDF

## Impact on Implementation
Ghost uses ExportKeyingMaterial("EXPORTER-ghost-session", nil, 32) as channel
binding for session token derivation. This replaces the original design's
tls_unique. Both client and server compute identical binding values from
the same TLS connection, enabling mutual token verification.

## Sources
- Go crypto/tls docs: ConnectionState.TLSUnique "nil for TLS 1.3"
- Go crypto/tls docs: ConnectionState.ExportKeyingMaterial
- RFC 8446 Section 7.5 (Exporters)
- RFC 9266 (tls-exporter channel binding)
- uTLS v1.8.2 source: ConnectionState mirrors Go stdlib behavior
