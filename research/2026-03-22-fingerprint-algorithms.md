# Fingerprint Algorithms — Research Notes

Date: 2026-03-22
Status: Reference material for Phase 7 test harness

---

## 1. JA4 (TLS Client Fingerprint)

**Spec:** https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

JA4 is a three-section hash of the TLS ClientHello:

```
JA4 = JA4_a + "_" + JA4_b + "_" + JA4_c
```

### JA4_a (plain-text prefix)

Format: `{proto}{version}{SNI}{ciphers_count}{ext_count}{ALPN}`

| Field          | Derivation                                                    |
|----------------|---------------------------------------------------------------|
| proto          | `t` for TCP/TLS, `q` for QUIC                                |
| version        | TLS record version → `10` / `11` / `12` / `13`               |
| SNI            | `d` if SNI present, `i` if absent                             |
| ciphers_count  | Number of cipher suites (excluding GREASE), 2 chars zero-padded |
| ext_count      | Number of extensions (excluding GREASE & SNI), 2 chars zero-padded |
| ALPN           | First and last character of first ALPN value, e.g. `h2`       |

### JA4_b (sorted cipher suites)

1. Collect cipher suite hex values, excluding GREASE.
2. Sort ascending.
3. Concatenate as 4-hex strings with commas: `1301,1302,1303,...`
4. SHA-256 hash → first 12 hex characters.

### JA4_c (sorted extensions + signature algorithms)

1. Collect extension type codes, excluding GREASE and SNI (0x0000).
2. Sort ascending.
3. Concatenate as 4-hex strings with commas.
4. Append `_` + sorted signature algorithms (from ext 0x000d) as 4-hex with commas.
5. SHA-256 hash → first 12 hex characters.

### GREASE values

GREASE values follow the pattern `0x?a?a` where `?` is any nibble 0–f and both bytes are identical:

```
0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
```

Detection: `hi == lo && (hi & 0x0f) == 0x0a` where `hi = v >> 8`, `lo = v & 0xff`.

### Chrome 146 expected JA4

```
t13d1517h2_8daaf6152771_02e483513dd2
```

---

## 2. Akamai HTTP/2 Fingerprint

**Spec:** https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf

Format: `{settings}|{window_update}|{priority_frames}|{pseudo_header_order}`

### Settings

SETTINGS frame key-value pairs in wire order:

| ID | Parameter                   | Chrome 146 |
|----|-----------------------------|------------|
| 1  | HEADER_TABLE_SIZE           | 65536      |
| 2  | ENABLE_PUSH                 | 0          |
| 4  | INITIAL_WINDOW_SIZE         | 6291456    |
| 6  | MAX_HEADER_LIST_SIZE        | 262144     |

String: `1:65536;2:0;4:6291456;6:262144`

### Window Update

Connection-level WINDOW_UPDATE sent after connection preface.
Chrome 146 value: `15663105`

### Priority / Priority Frames

Priority information from PRIORITY frames or HEADERS priority field.
Chrome 146 value: `0` (no explicit PRIORITY frames in modern Chrome).

### Pseudo-Header Order

Order of HTTP/2 pseudo-headers in the first HEADERS frame:

| Letter | Pseudo-Header |
|--------|---------------|
| m      | :method       |
| a      | :authority    |
| s      | :scheme       |
| p      | :path         |

Chrome 146 order: `m,a,s,p`

---

## 3. Echo Services

### tls.peet.ws

- URL: `https://tls.peet.ws/api/all`
- Returns: JA4, JA3, AKAMAI fingerprint, TLS extensions, cipher suites, ALPN, etc.
- JSON response includes `tls.ja4`, `http2.akamai_fingerprint`, `tls.extensions[]`
- Free, no auth required.

### Other services (not currently used)

- `https://tls.browserleaks.com/json` — similar but less detailed H2 info
- `https://check.ja4db.com/` — JA4 database lookup
- Wireshark/tshark — local pcap analysis for ground truth

---

## 4. Go Libraries

### refraction-networking/utls

- Module: `github.com/refraction-networking/utls`
- Version used: `v1.8.2`
- Provides `ClientHelloID` presets (e.g. `HelloChrome_Auto`) that mimic browser TLS fingerprints.
- We use it in client mode to establish a uTLS connection, then layer HTTP/2 on top via `x/net/http2`.

### golang.org/x/net/http2

- Used for HTTP/2 `ClientConn` creation on top of the uTLS connection.
- `http2.Transport.NewClientConn(conn, ...)` allows HTTP/2 over an existing `net.Conn`.
- Also provides `http2/hpack` for HPACK header decoding in analyze mode.

### bogdanfinn/fhttp (Ghost main transport)

- Module: `github.com/bogdanfinn/fhttp`
- Ghost's primary HTTP client — not used in fpcheck tools.
- The fpcheck tools are intentionally independent of Ghost's internal transport to serve as an external validation layer.

---

## 5. Implementation Notes

### Why fpcheck does NOT import Ghost internals

The fingerprint checker validates that Ghost's transport produces correct fingerprints.
If it imported Ghost internals, a bug in the transport layer could silently affect both the implementation and the test, creating a false positive.

The three modes provide layered validation:
1. **client mode** — end-to-end: connects via uTLS to a real echo service
2. **analyze mode** — offline: parses raw TLS/H2 captures for CI/deterministic testing
3. **baseline mode** — reference data: dumps expected values for manual review

### ALPS extension code

Chrome uses extension `17613` (0x44DD) for ALPS (Application-Layer Protocol Settings).
This is distinct from ALPN (0x0010). The ALPS extension carries application-level settings
in the TLS handshake for protocols like HTTP/2.
