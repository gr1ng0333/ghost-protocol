# Research: gomobile bind with gVisor + uTLS

Date: 2026-03-24
Stage: 6.1 (Android VpnService + gVisor Netstack)
Query: Can gomobile bind compile Go packages importing gVisor netstack and uTLS?

## Summary

gomobile bind can compile packages with gVisor netstack and uTLS into Android
AAR, but requires careful version pinning. Key risks are uTLS go.mod requiring
Go 1.24+, gomobile issues on Go 1.22-1.23 (vendor dir, reentrant callbacks),
and gVisor's fdbased endpoint historically using sendmmsg on non-socket TUN fds.
Current gVisor master has a fix that degrades to writev for non-socket fds.

## Key Findings

- gomobile bind works with gVisor netstack; GOOS=android matches linux build
  tags, so gVisor's fdbased endpoint (//go:build linux) compiles for Android
- uTLS current HEAD requires Go 1.24 in go.mod; Ghost pins uTLS v1.8.2 which
  may have a lower Go requirement — verify before upgrading
- gVisor fdbased sendmmsg fix: current master's sendBatch degrades to
  writePacket (writev) for non-socket fds, fixing "socket operation on
  non-socket" error with Android TUN fds
- AAR size estimate: ~11MB per ABI, ~25-40MB total for multi-ABI builds;
  using -target=android/arm64 and -ldflags="-s -w" reduces size
- gomobile has known issues with vendor/ directory on Go 1.22; workaround
  is to remove vendor/ before gomobile bind
- Go→Kotlin→Go reentrant callbacks can crash on Go 1.22.5/1.22.6
- Reference projects: outline-go-tun2socks, tun2socks, clash Go core all
  use similar gomobile + netstack patterns

## Impact on Implementation

- mobile/build.sh targets android/arm64 only and uses -ldflags="-s -w"
- gVisor netstack setup in netstack_linux.go uses fdbased endpoint which
  will work on Android thanks to the writev fallback for non-socket fds
- Go toolchain version should be tested against gomobile before upgrading
- No vendor/ directory is used in the project (go modules only)

## Sources

- golang.org/x/mobile gomobile documentation
- gVisor pkg/tcpip/link/fdbased source (sendBatch writev fallback)
- uTLS go.mod (go 1.24 directive)
- gomobile GitHub issues (vendor, reentrant callbacks, Go 1.22)
- outline-go-tun2socks, xxf098/go-tun2socks-build (AAR size references)
