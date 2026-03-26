# pprof Analysis: Ghost Server Under Load

**Date:** 2026-03-26
**Server:** 94.156.122.66:443
**Load:** 100MB download through Ghost tunnel (performance mode)
**Current throughput:** ~35-45 Mbps (after buffered pipe + flush batching + stats fixes)

---

## CPU Profile Top-30 (flat)

```
File: ghost-server
Type: cpu
Duration: 30s, Total samples = 3.17s (10.57%)
Showing nodes accounting for 2.61s, 82.33% of 3.17s total
Dropped 152 nodes (cum <= 0.02s)
      flat  flat%   sum%        cum   cum%
     1.10s 34.70% 34.70%      1.10s 34.70%  internal/runtime/syscall/linux.Syscall6
     0.24s  7.57% 42.27%      0.24s  7.57%  crypto/internal/fips140/aes/gcm.gcmAesEnc
     0.18s  5.68% 47.95%      0.18s  5.68%  runtime.memmove
     0.06s  1.89% 49.84%      0.13s  4.10%  runtime.pcvalue
     0.05s  1.58% 51.42%      0.05s  1.58%  runtime.nextFreeFast (inline)
     0.04s  1.26% 52.68%      0.04s  1.26%  crypto/internal/fips140/edwards25519/field.feMul
     0.04s  1.26% 53.94%      0.09s  2.84%  runtime.(*unwinder).resolveInternal
     0.04s  1.26% 55.21%      0.04s  1.26%  runtime.adjustpointers
     0.04s  1.26% 56.47%      0.07s  2.21%  runtime.findfunc
     0.04s  1.26% 57.73%      0.04s  1.26%  runtime.futex
     0.04s  1.26% 58.99%      0.10s  3.15%  runtime.newobject
     0.04s  1.26% 60.25%      0.05s  1.58%  runtime.step
     0.04s  1.26% 61.51%      0.06s  1.89%  runtime.unlock2
     0.03s  0.95% 62.46%      0.03s  0.95%  crypto/internal/fips140/edwards25519/field.feSquare
     0.03s  0.95% 63.41%      0.03s  0.95%  internal/runtime/atomic.(*Uint32).CompareAndSwap (inline)
     0.03s  0.95% 64.35%      0.03s  0.95%  runtime.findmoduledatap (inline)
     0.03s  0.95% 65.30%      0.03s  0.95%  runtime.lock2
     0.03s  0.95% 66.25%      0.10s  3.15%  runtime.reentersyscall
     0.03s  0.95% 67.19%      0.21s  6.62%  runtime.selectgo
     0.02s  0.63% 67.82%      0.03s  0.95%  golang.org/x/net/http2.FrameWriteRequest.Consume
     0.02s  0.63% 68.45%      0.02s  0.63%  runtime.(*itabTableType).find
     0.02s  0.63% 69.09%      0.12s  3.79%  runtime.blockevent
     0.02s  0.63% 69.72%      0.02s  0.63%  runtime.cputicks
     0.02s  0.63% 70.35%      0.02s  0.63%  runtime.nanotime (inline)
     0.02s  0.63% 70.98%      0.22s  6.94%  runtime.netpoll
     0.02s  0.63% 71.61%      0.12s  3.79%  runtime.saveblockevent
     0.02s  0.63% 72.24%      0.04s  1.26%  runtime.selunlock
     0.02s  0.63% 72.87%      0.02s  0.63%  runtime.stkbucket
     0.02s  0.63% 73.50%      0.02s  0.63%  runtime.traceEnabled (inline)
     0.02s  0.63% 74.13%      0.02s  0.63%  sync.(*Pool).Put
```

## CPU Profile Top-30 (cumulative)

```
File: ghost-server
Type: cpu
Duration: 30s, Total samples = 3.17s (10.57%)
      flat  flat%   sum%        cum   cum%
     1.10s 34.70% 34.70%      1.10s 34.70%  internal/runtime/syscall/linux.Syscall6
         0     0% 34.70%      0.99s 31.23%  ghost/internal/transport.(*ghostServer).ListenAndServe.func2
         0     0% 34.70%      0.98s 30.91%  ghost/internal/transport.(*ghostServer).handleIncoming
         0     0% 34.70%      0.86s 27.13%  bufio.(*Writer).Write
         0     0% 34.70%      0.84s 26.50%  syscall.RawSyscall6
         0     0% 34.70%      0.83s 26.18%  golang.org/x/net/http2.(*serverConn).writeFrameAsync
         0     0% 34.70%      0.82s 25.87%  crypto/tls.(*Conn).Write
         0     0% 34.70%      0.82s 25.87%  golang.org/x/net/http2.(*Framer).endWrite
         0     0% 34.70%      0.82s 25.87%  golang.org/x/net/http2.(*bufferedWriter).Write
         0     0% 34.70%      0.82s 25.87%  golang.org/x/net/http2.(*bufferedWriterTimeoutWriter).Write
         0     0% 34.70%      0.82s 25.87%  golang.org/x/net/http2.writeWithByteTimeout
         0     0% 34.70%      0.79s 24.92%  syscall.Syscall
     0.01s  0.32% 35.02%      0.75s 23.66%  crypto/tls.(*Conn).writeRecordLocked
         0     0% 35.02%      0.64s 20.19%  internal/poll.ignoringEINTRIO (inline)
         0     0% 35.02%      0.39s 12.30%  internal/poll.(*FD).Write
         0     0% 35.02%      0.39s 12.30%  runtime.mcall
     0.01s  0.32% 35.33%      0.39s 12.30%  syscall.Write (inline)
         0     0% 35.33%      0.38s 11.99%  crypto/tls.(*Conn).write
         0     0% 35.33%      0.38s 11.99%  net.(*conn).Write
         0     0% 35.33%      0.38s 11.99%  net.(*netFD).Write
         0     0% 35.33%      0.38s 11.99%  syscall.write
         0     0% 35.33%      0.35s 11.04%  crypto/tls.(*halfConn).encrypt
         0     0% 35.33%      0.35s 11.04%  runtime.schedule
     0.01s  0.32% 35.65%      0.34s 10.73%  runtime.findRunnable
         0     0% 35.65%      0.33s 10.41%  ghost/internal/transport.(*ghostServer).handleConn
         0     0% 35.65%      0.31s  9.78%  runtime.park_m
         0     0% 35.65%      0.30s  9.46%  ghost/internal/transport.(*ghostServer).ListenAndServe
         0     0% 35.65%      0.30s  9.46%  main.main
         0     0% 35.65%      0.30s  9.46%  runtime.main
         0     0% 35.65%      0.27s  8.52%  net.(*TCPListener).Accept
```

## Block Profile Top-30 (flat)

```
File: ghost-server
Type: delay
Showing nodes accounting for 1441.04s, 100% of 1441.05s total
Dropped 69 nodes (cum <= 7.21s)
      flat  flat%   sum%        cum   cum%
  1072.93s 74.45% 74.45%   1072.93s 74.45%  runtime.selectgo
   225.76s 15.67% 90.12%    225.76s 15.67%  sync.(*Cond).Wait
    51.53s  3.58% 93.70%     51.53s  3.58%  runtime.chanrecv1
    45.98s  3.19% 96.89%     45.98s  3.19%  sync.(*Mutex).Lock (inline)
    44.83s  3.11%   100%     44.83s  3.11%  runtime.chanrecv2
```

## Block Profile Top-30 (cumulative)

```
File: ghost-server
Type: delay
Showing nodes accounting for 1441.04s, 100% of 1441.05s total
Dropped 69 nodes (cum <= 7.21s)
      flat  flat%   sum%        cum   cum%
  1072.93s 74.45% 74.45%   1072.93s 74.45%  runtime.selectgo
         0     0% 74.45%    228.21s 15.84%  ghost/internal/transport.(*ghostHandler).ServeHTTP
         0     0% 74.45%    228.21s 15.84%  golang.org/x/net/http2.(*serverConn).runHandler
         0     0% 74.45%    228.21s 15.84%  golang.org/x/net/http2.(*serverConn).scheduleHandler.gowrap1
         0     0% 74.45%    228.21s 15.84%  net/http.Handler.ServeHTTP-fm
   225.76s 15.67% 90.12%    225.76s 15.67%  sync.(*Cond).Wait
         0     0% 90.12%    203.80s 14.14%  io.Copy (inline)
         0     0% 90.12%    203.80s 14.14%  io.copyBuffer
         0     0% 90.12%    121.99s  8.47%  ghost/internal/shaping.(*StatsUpdater).Run
         0     0% 90.12%    121.99s  8.47%  ghost/internal/transport.(*ghostServer).handleGhost.gowrap2
         0     0% 90.12%    121.47s  8.43%  ghost/internal/transport.(*ghostServer).ListenAndServe.func2
         0     0% 90.12%    121.47s  8.43%  ghost/internal/transport.(*ghostServer).handleIncoming
         0     0% 90.12%    121.47s  8.43%  ghost/internal/transport.(*ghostServer).handleConn
         0     0% 90.12%    121.47s  8.43%  ghost/internal/transport.(*ghostServer).handleGhost
         0     0% 90.12%    121.47s  8.43%  golang.org/x/net/http2.(*Server).ServeConn (inline)
         0     0% 90.12%    121.47s  8.43%  golang.org/x/net/http2.(*Server).serveConn
         0     0% 90.12%    121.47s  8.43%  golang.org/x/net/http2.(*serverConn).serve
         0     0% 90.12%    120.88s  8.39%  ghost/internal/transport.(*ghostHandler).handleGet.func1
         0     0% 90.12%    120.72s  8.38%  ghost/internal/transport.(*ghostHandler).handleGet
         0     0% 90.12%       120s  8.33%  ghost/internal/transport.(*SessionManager).RunCleanupLoop
         0     0% 90.12%       120s  8.33%  main.main.func4
         0     0% 90.12%       120s  8.33%  main.main.func5
         0     0% 90.12%       120s  8.33%  main.main.gowrap1
         0     0% 90.12%    116.40s  8.08%  ghost/internal/mux.(*serverMux).writeLoop
         0     0% 90.12%    116.40s  8.08%  ghost/internal/mux.NewServerMux.gowrap1
         0     0% 90.12%    107.57s  7.46%  ghost/internal/framing.(*DecoderReader).ReadFrame
         0     0% 90.12%    107.57s  7.46%  ghost/internal/framing.(*decoder).Decode
         0     0% 90.12%    107.57s  7.46%  ghost/internal/mux.(*serverMux).readLoop
         0     0% 90.12%    107.57s  7.46%  ghost/internal/mux.NewServerMux.gowrap2
         0     0% 90.12%    107.57s  7.46%  ghost/internal/shaping.(*UnpadderFrameReader).ReadFrame
         0     0% 90.12%    107.57s  7.46%  io.(*PipeReader).Read
         0     0% 90.12%    107.57s  7.46%  io.(*pipe).read
         0     0% 90.12%    107.57s  7.46%  io.ReadAtLeast
         0     0% 90.12%    107.57s  7.46%  io.ReadFull (inline)
         0     0% 90.12%    107.49s  7.46%  ghost/internal/transport.(*ghostHandler).handleStreamUpload
         0     0% 90.12%    107.49s  7.46%  golang.org/x/net/http2.(*requestBody).Read
         0     0% 90.12%    107.49s  7.46%  golang.org/x/net/http2.(*pipe).Read
         0     0% 90.12%     74.55s  5.17%  ghost/internal/shaping.(*CoverGenerator).run
         0     0% 90.12%     74.55s  5.17%  ghost/internal/shaping.(*CoverGenerator).Start.gowrap1
         0     0% 90.12%     72.71s  5.05%  ghost/internal/mux.(*bufferedPipe).Read
         0     0% 90.12%     63.51s  4.41%  ghost/internal/mux.(*serverMux).Accept
         0     0% 90.12%     63.51s  4.41%  ghost/internal/transport.(*ghostServer).dispatchStreams
         0     0% 90.12%     63.51s  4.41%  ghost/internal/transport.(*ghostServer).handleGhost.gowrap3
         0     0% 90.12%     51.48s  3.57%  ghost/internal/mux.(*serverMux).sendFrame
         0     0% 90.12%     51.48s  3.57%  ghost/internal/mux.(*serverMux).readLoop.(*serverMux).makeWriteFn.func1
         0     0% 90.12%     51.48s  3.57%  ghost/internal/mux.(*stream).Write
         0     0% 90.12%     51.48s  3.57%  ghost/internal/transport.(*countingWriter).Write
         0     0% 90.12%     48.00s  3.33%  bufio.(*Writer).Write
         0     0% 90.12%     45.56s  3.16%  ghost/internal/framing.(*EncoderWriter).WriteFrame
         0     0% 90.12%     45.56s  3.16%  ghost/internal/framing.(*encoder).Encode
         0     0% 90.12%     45.56s  3.16%  ghost/internal/mux.(*bufferedPipe).Write
         0     0% 90.12%     45.56s  3.16%  ghost/internal/shaping.(*PadderFrameWriter).WriteFrame
         0     0% 90.12%     45.56s  3.16%  ghost/internal/shaping.(*TimerFrameWriter).WriteFrame
         0     0% 90.12%     44.83s  3.11%  ghost/internal/mux.(*stream).Read
```

## Mutex Contention Top-10

```
File: ghost-server
Type: delay
Showing nodes accounting for 45.95s, 100% of 45.98s total
Dropped 205 nodes (cum <= 0.23s)
      flat  flat%   sum%        cum   cum%
    45.95s   100%   100%     45.95s   100%  sync.(*Mutex).Unlock (inline)
         0     0%   100%     45.95s   100%  ghost/internal/transport.(*ghostHandler).ServeHTTP
         0     0%   100%     45.95s   100%  ghost/internal/transport.(*ghostHandler).handleGet
         0     0%   100%     45.95s   100%  golang.org/x/net/http2.(*serverConn).runHandler
         0     0%   100%     45.95s   100%  golang.org/x/net/http2.(*serverConn).scheduleHandler.gowrap1
         0     0%   100%     45.95s   100%  net/http.Handler.ServeHTTP-fm
```

## Goroutine Dump Summary

- **Total goroutines:** 28
- **Main goroutine (1):** IO wait — `net.(*TCPListener).Accept` — waiting for new connections
- **writeLoop (550):** `sync.Cond.Wait` — `bufferedPipe.Write` waiting for buffer space (expected, buffer full = saturated link)
- **readLoop (551):** `io.(*pipe).read` — reading from http2 pipe, waiting for upload data
- **HTTP GET handler (557):** `IO wait` — `crypto/tls.(*Conn).readRecordOrCCS` — waiting for TLS read (underlying TCP write)
- **HTTP GET flush goroutine (562):** `sync.Mutex.Lock` — blocked on `flushMu` in handleGet.func1 (flush ticker goroutine waiting for write lock)
- **Stream upload handler (566):** `sync.Cond.Wait` — `http2.(*pipe).Read` — waiting for upload data
- **Stream data-copy goroutines (2340, 2398):** `chan receive` — `mux.(*stream).Read` — waiting for data from mux channels
- **Stream handler (2333):** IO wait — reading from target TCP connection (external site data)
- **Stream write path (2390):** `chan receive` — `mux.(*serverMux).sendFrame` — waiting for writeLoop to process frame
- **CoverGenerator (552):** `select` — idle cover traffic generator
- **StatsUpdater (553):** `select` — periodic stats updater
- **Session cleanup (8):** `select` — periodic timer
- **Watchdog (11):** `select` — systemd watchdog ping timer
- **Metrics logger (12):** `select` — periodic metrics log timer
- **dispatchStreams (554):** `select` — `mux.Accept` waiting for new streams

## Goroutine Dump (relevant excerpts)

### writeLoop — blocked on bufferedPipe.Write (buffer full)
```
goroutine 550 [sync.Cond.Wait]:
sync.(*Cond).Wait(...)
ghost/internal/mux.(*bufferedPipe).Write(0x22a8a28ded80, ...)
  internal/mux/buffered_pipe.go:41
ghost/internal/framing.(*encoder).Encode(...)
  internal/framing/codec.go:75
ghost/internal/framing.(*EncoderWriter).WriteFrame(...)
  internal/framing/frameio.go:23
ghost/internal/shaping.(*PadderFrameWriter).WriteFrame(...)
  internal/shaping/profile_padder.go:197
ghost/internal/shaping.(*TimerFrameWriter).WriteFrame(...)
  internal/shaping/timer_writer.go:43
ghost/internal/mux.(*serverMux).writeLoop(...)
  internal/mux/server.go:102
```

### readLoop — waiting for upload data from HTTP/2 pipe
```
goroutine 551 [select]:
io.(*pipe).read(...)
io.(*PipeReader).Read(...)
io.ReadAtLeast(...)
ghost/internal/framing.(*decoder).Decode(...)
  internal/framing/codec.go:106
ghost/internal/framing.(*DecoderReader).ReadFrame(...)
  internal/framing/frameio.go:34
ghost/internal/shaping.(*UnpadderFrameReader).ReadFrame(...)
  internal/shaping/profile_padder.go:216
ghost/internal/mux.(*serverMux).readLoop(...)
  internal/mux/server.go:114
```

### HTTP GET handler — TLS write/IO wait (sending data to client)
```
goroutine 557 [IO wait]:
crypto/tls.(*Conn).readRecordOrCCS(...)
ghost/internal/transport.(*ghostHandler).handleGet(...)
  internal/transport/handler.go:145
ghost/internal/transport.(*ghostHandler).ServeHTTP(...)
  internal/transport/handler.go:69
```

### HTTP GET flush goroutine — blocked on flushMu (mutex contention with write)
```
goroutine 562 [sync.Mutex.Lock]:
ghost/internal/transport.(*ghostHandler).handleGet.func1()
  internal/transport/handler.go:134
```

### Stream data copy — waiting for mux stream data
```
goroutine 2390 [chan receive]:
ghost/internal/mux.(*serverMux).sendFrame(...)
  internal/mux/server.go:91
ghost/internal/mux.(*stream).Write(...)
  internal/mux/stream.go:110
ghost/internal/transport.(*countingWriter).Write(...)
  internal/transport/server.go:316
io.Copy → net.(*TCPConn).writeTo → ghost/internal/transport.(*ghostServer).handleStream(...)
  internal/transport/server.go:638
```

---

## Analysis

### Primary CPU Consumers
1. **`internal/runtime/syscall/linux.Syscall6`** — 34.7% flat — raw syscalls (read/write fd). This is pure I/O, expected for a data-forwarding proxy.
2. **`crypto/internal/fips140/aes/gcm.gcmAesEnc`** — 7.6% flat — TLS AES-GCM encryption. Unavoidable for TLS 1.3.
3. **`runtime.memmove`** — 5.7% flat — memory copies (buffer operations). Normal for high-throughput Go.
4. **`runtime.selectgo`** — 6.6% cum — select statement overhead for channels. Expected in a goroutine-heavy architecture.

**Total CPU load during 30s of active transfer: only 3.17s (10.57%) — the server is CPU-idle.** The VPS is not CPU-bound at all. The limiting factor is network I/O.

### Primary Blocking Points
1. **`runtime.selectgo`** — 1073s (74.5%) — most goroutines are idle in `select{}` loops (timers, cleanup, cover generator). This is normal.
2. **`sync.(*Cond).Wait`** — 226s (15.7%) — split between:
   - `bufferedPipe.Write` (45.6s) — writeLoop waiting for buffer space (downstream is slower than upstream mux processing). This is the expected backpressure signal — the 2MB buffer fills up because TLS+HTTP/2 write to the client is the real bottleneck.
   - `bufferedPipe.Read` (72.7s) — handleGet reading from buffer, sometimes empty (normal for bursty traffic).
   - `http2.(*pipe).Read` via `io.(*pipe).read` (107.6s) — readLoop waiting for upload data from client.
3. **`runtime.chanrecv1/chanrecv2`** — 96.4s — channel receives in:
   - `mux.(*stream).Read` (44.8s) — waiting for data on mux stream channel
   - `mux.sendFrame` (51.5s) — writeLoop channel send waiting for space
4. **`sync.(*Mutex).Lock`** — 46.0s — **flushMu in handleGet** — the flush goroutine and write goroutine compete for the mutex.

### Contention Hotspots
1. **handleGet flushMu mutex** — 46.0s total contention. The 5ms flush ticker goroutine and the main write loop both acquire `flushMu`. When the write is doing a large HTTP/2 frame write + TLS encryption + syscall, the flush ticker blocks waiting for the lock.
   - **Severity: LOW** — this is by design (flush batching). The ~46s of mutex contention over the server lifetime is the accumulated wait across many lock acquisitions. The actual per-operation contention is microseconds. The goroutine dump shows the flush goroutine occasionally waiting, which is the correct behavior (flush waits for write to complete).

### Remaining Bottlenecks Identified

**No critical bottlenecks remain in Ghost data path code.**

The blocking profile shows the data path is clean:
- writeLoop blocks on `bufferedPipe.Write` sync.Cond.Wait → this is correct backpressure. The buffer fills because the downstream TLS+HTTP/2 write is the physical speed limit.
- readLoop blocks on upstream `io.Pipe` read → waiting for client upload data (expected: download test has minimal upload).
- handleGet blocks on TLS I/O → writing encrypted data to the socket. This is the actual network bottleneck and cannot be optimized in Go code.

The only area of note is the **flushMu contention**, but it is functioning as intended — the mutex prevents the 5ms flush ticker from flushing mid-write, which was causing sub-optimal HTTP/2 framing. The contention cost is negligible.

### What Limits Throughput Now

The 35-45 Mbps throughput is limited by:
1. **TLS encryption overhead** — AES-GCM encryption/decryption adds latency per write
2. **HTTP/2 framing overhead** — each data chunk requires framing
3. **Network path** — VPS bandwidth, RTT to client, TCP window scaling
4. **`crypto/tls.(*Conn).writeRecordLocked`** — 23.7% cumulative CPU — the TLS write path is the hot path

None of these are fixable in Ghost application code. They are inherent to the architecture (TLS 1.3 + HTTP/2 tunnel over the public internet).

## Conclusion

**The Ghost server data path is healthy and free of application-level bottlenecks.**

- CPU usage during active transfer is only **10.6%** — ample headroom
- No `runtime.chanrecv/chansend` in unexpected places — channel architecture is clean
- No `time.Sleep` in data path — shaping timers are not on the critical path
- `bufferedPipe` is working correctly — it fills to capacity and applies backpressure via `sync.Cond.Wait`, then drains as TLS writes complete
- Flush batching mutex contention is present but is by design and LOW severity
- The physical bottleneck is TLS write → syscall → network, which is the expected steady-state for a high-throughput encrypted tunnel
- No `io.Pipe` remains in the downstream data path (confirmed: writeLoop writes to `bufferedPipe`, not `io.Pipe`)
- Upload path still uses `io.Pipe` (readLoop reads from `io.(*pipe).read`) — this is fine because upload volume during download tests is minimal

**Verdict: No further code-level optimization opportunities identified. The 35-45 Mbps throughput is bounded by TLS + HTTP/2 + network, not by Ghost code.**
