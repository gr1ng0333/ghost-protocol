# Research: Android VpnService Implementation 2025-2026

Date: 2026-03-24
Stage: 6.1 (Android VpnService + gVisor Netstack)
Query: Android 14+ VpnService best practices, FGS type, permissions, fd handling

## Summary

Android 14+ requires explicit foreground service types. For VPN services, the
correct type is specialUse with subtype "vpn" (per AOSP ToyVpn sample). The
dataSync type has a 6-hour timeout on Android 15 and must NOT be used for
long-running VPN. TUN fd is obtained via Builder.establish().detachFd() which
transfers ownership to native/Go code.

## Key Findings

- FGS type for VPN: foregroundServiceType="specialUse" with
  PROPERTY_SPECIAL_USE_FGS_SUBTYPE="vpn" (AOSP ToyVpn sample)
- Required permissions: INTERNET, FOREGROUND_SERVICE,
  FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS (Android 13+)
- Service must declare BIND_VPN_SERVICE permission and intent-filter
  for android.net.VpnService
- Builder.setBlocking(true) recommended for Go/gVisor-based VPN stacks
- detachFd() transfers fd ownership; Go must close fd on shutdown
- MTU: 1280 (IPv6-safe minimum) to 1500 (standard Ethernet); 1500 chosen
- onRevoke() may be called on non-main thread; must handle gracefully
- Android 15 dataSync FGS has 6-hour timeout — DO NOT use for VPN
- addDisallowedApplication(packageName) prevents routing loop
- VpnService.protect() needed if Go creates sockets directly (not needed
  when using gVisor netstack which reads/writes raw packets on TUN fd)
- always-on VPN requires android:exported="true" and
  SUPPORTS_ALWAYS_ON meta-data

## Impact on Implementation

- GhostVpnService uses specialUse FGS type (not dataSync)
- Builder configured with setBlocking(true), MTU 1500, full tunnel routes
- detachFd() used, Go owns fd lifecycle
- protect() not needed — gVisor reads raw IP packets from TUN, Ghost's
  transport sockets are created by Go's net.Dial which uses the OS
  network stack outside the VPN tunnel (Ghost server IP excluded via
  addDisallowedApplication). If routing loop occurs, protect() via
  JNI callback would be needed (deferred to Stage 6.3).

## Sources

- Android developer documentation: VpnService, VpnService.Builder
- AOSP ToyVpn sample (foregroundServiceType specialUse)
- Android 14 foreground service type requirements
- Android 15 FGS timeout behavior changes
- ParcelFileDescriptor.detachFd() documentation
