# POST Batching Analysis (Issue #19)

## Current behavior

The `postWriter` in `pipeline.go` wraps `PipelineConn.Send` as an
`io.Writer`. Each `Write()` call sends the data as a single HTTP/2
POST request body via `conn.Send()`, then immediately closes the
response body. The call chain is:

    mux stream.Write → writeFn → sendFrame → writeLoop → FrameWriter.WriteFrame
      → EncoderWriter → Encoder.Encode → postWriter.Write → conn.Send (one POST)

Every Ghost frame that the encoder serializes results in exactly one
HTTP/2 POST request to the server. For bulk data, a single
application write may be split into multiple MaxPayloadSize (16 000 B)
chunks, each producing its own POST.

## Proposed change

Buffer frames in `postWriter` for up to 5 ms or 32 KB (whichever
comes first), then flush as a single POST containing all buffered
frame bytes.

## Tradeoff analysis

- **Pro:** Fewer HTTP/2 requests, fewer HPACK-compressed request
  headers on the wire.
- **Pro:** Slightly fewer round-trip-like interactions with the HTTP/2
  layer (less framing overhead in terms of HEADERS frames).
- **Con:** Adds up to 5 ms latency to *every* frame, including
  interactive traffic (SSH keystrokes, DNS lookups, web page resource
  fetches). This directly harms user-perceived latency.
- **Con:** Adds significant complexity: flush timer, buffer pool,
  partial-write edge cases, clean shutdown of the timer goroutine,
  and subtle concurrency between the timer flush and the next Write.
- **Con:** The overhead being saved is small. HTTP/2 multiplexes all
  POSTs on a single TCP connection and a single TLS record stream.
  The per-request overhead is:
    - One HEADERS frame (~9 B wire overhead + HPACK-compressed
      pseudo-headers and path — likely 20–40 B after compression).
    - One DATA frame (9 B wire header).
  For a 16 000 B Ghost frame, that is ~50 B overhead per POST, or
  roughly 0.3%. Even for small interactive frames (e.g. a 50 B SSH
  keystroke), the overhead is ~50 B / 100 B = 50%, but the absolute
  cost is trivial on modern links and the latency penalty of batching
  is far more harmful than saving those bytes.
- **Con:** Batching changes the request cadence in a way that might
  *reduce* resemblance to real Chrome traffic patterns, potentially
  making the tunnel more detectable rather than less.

## Recommendation

The overhead of one-POST-per-frame is not significant in practice.
HTTP/2 already amortizes TCP and TLS overhead across the shared
connection; the incremental cost of additional HEADERS + DATA frames
is on the order of tens of bytes per request. For bulk transfers the
ratio is negligible (<0.5%). For interactive traffic, the 5 ms
batching delay would be user-visible and harmful.

A ≥20% throughput improvement is not plausible from this change.
Rough math: even in the worst case (many tiny frames), the bottleneck
is TLS encryption and TCP congestion control, not HTTP/2 framing
overhead. Benchmarking would confirm, but the theoretical ceiling is
far below 20%.

## Decision

**SKIP.** Close Issue #19. The one-POST-per-frame design is the right
tradeoff for Ghost's use case: minimal added complexity, no latency
penalty, and the overhead is already negligible under HTTP/2
multiplexing. If future profiling (Phase 7.1) reveals HTTP/2 framing
as an actual bottleneck, the batching layer can be added as a
`FrameWriter` middleware without changing the mux or pipeline APIs.
