# Troubleshooting

## Connection Issues

### "Connection timeout" / "dial tcp: i/o timeout"

1. **Server running?** SSH in, check: `sudo systemctl status ghost-server`
2. **Firewall?** Verify port 443 is open: `sudo nft list ruleset | grep 443`
3. **DNS?** Confirm domain resolves to VPS IP: `dig YOUR_DOMAIN`
4. **Client config?** `server.addr` and `server.sni` must match the server's domain
5. **VPS provider?** Some providers block port 443 by default — check their firewall/security group settings

### "Freeze detected, reconnecting"

This is normal TSPU behavior — the DPI system silently drops packets on the connection. Ghost detects the freeze (no data for the health check interval) and reconnects automatically.

If it happens constantly:
- Switch to **Stealth** mode: `shaping.default_mode: "stealth"`
- Check if the VPS IP or ASN is blocklisted (try a different VPS provider/region)
- Verify the server isn't overloaded: check health endpoint `curl http://127.0.0.1:9090/health`

### "TLS handshake error"

- **Auto-cert mode:** Domain must resolve to the VPS, and port 80 must be open for ACME HTTP-01 challenges
- **Manual certs:** Verify `tls.cert_file` and `tls.key_file` paths exist and are readable by the `ghost` user
- **Certificate expired:** Check with `openssl s_client -connect YOUR_DOMAIN:443 </dev/null 2>/dev/null | openssl x509 -noout -dates`

### "Auth failed" / "invalid session token"

Keys don't match between client and server. Fix:

1. Run `ghost-keygen` again
2. Paste server section into `server.yaml` (all three keys)
3. Paste client section into `client.yaml` (two keys)
4. Restart server: `sudo systemctl restart ghost-server`
5. Restart client

Common mistake: swapping `server_private_key` and `client_private_key`. The keygen output labels which section goes where — follow it exactly.

### Client connects but no traffic flows

- Check `proxy.socks5` address matches what your browser/app uses (default: `127.0.0.1:1080`)
- In TUN mode, verify the `ghost0` interface exists: `ip link show ghost0`
- Check server logs for "session" messages: `sudo journalctl -u ghost-server --since "5 min ago"`

## Performance Issues

### Slow speed in Balanced/Stealth mode

Expected. Traffic shaping adds padding and timing delays to mimic real Chrome browsing patterns. Typical throughput:
- Performance: ~78 Mbps
- Balanced: ~58 Mbps
- Stealth: ~58 Mbps (with cover traffic overhead)

Switch to Performance mode if DPI isn't a concern.

### Slow speed in Performance mode

1. **Check VPS bandwidth directly:** `iperf3 -c YOUR_SERVER_IP` (install iperf3 on both sides)
2. **Check server CPU:** `htop` on VPS — shaping is CPU-intensive
3. **Check client CPU:** weak devices (especially Android) may bottleneck on crypto
4. **Check for packet loss:** `mtr YOUR_DOMAIN` from client
5. **Check active sessions:** `curl http://127.0.0.1:9090/health` — too many active sessions sharing bandwidth?

### High latency

Ghost adds ~2-5ms overhead in Performance mode due to HTTP/2 framing + TLS. In Stealth mode, timing jitter intentionally adds variable delays.

For latency-sensitive use (gaming, video calls), use Performance mode.

## Android Issues

### VPN won't start

- **Permission:** Tap Connect — Android should prompt for VPN permission. If it doesn't, go to Settings → Apps → Ghost → Permissions
- **Keys:** Verify server public key and client private key are entered correctly (64 hex characters each, no spaces)
- **Server address:** Must include port, e.g., `YOUR_DOMAIN:443`

### VPN disconnects on screen off

- **Battery optimization:** Must be disabled for Ghost. Go to Settings → Apps → Ghost → Battery → Unrestricted
- **Always-on VPN:** Enable in Settings → Network → VPN → Ghost → gear icon → Always-on VPN
- **Device-specific:** Some manufacturers (Xiaomi, Huawei, Samsung) aggressively kill background apps. Search for your device at [dontkillmyapp.com](https://dontkillmyapp.com/)

### No internet after connecting VPN

- Check server is reachable (test from another device/browser first)
- Check keys match server config
- Try restarting the app
- Check Android logs: `adb logcat | grep -i ghost`

## Server Issues

### High memory usage

- Check `sessions.max_sessions` in config — reduce if needed (default: 10, recommended: 5 for 2-5 users)
- Check health endpoint for session count: `curl http://127.0.0.1:9090/health`
- Check for leaked sessions: restart server to clear all sessions

### Certificate renewal failed

- Port 80 **must** be open for Let's Encrypt HTTP-01 challenges
- Domain must resolve to the VPS IP (not behind Cloudflare proxy)
- Check logs: `sudo journalctl -u ghost-server | grep -i cert`
- Manual fix: delete cert cache and restart: `sudo rm -rf /var/lib/ghost/certs/* && sudo systemctl restart ghost-server`

### Server won't start after update

- Check config format: `cat /etc/ghost/server.yaml` — YAML is indentation-sensitive
- Check binary permissions: `ls -la /usr/local/bin/ghost-server` — must be executable
- Check capabilities: `getcap /usr/local/bin/ghost-server` — should show `cap_net_bind_service`
- Check logs for the actual error: `sudo journalctl -u ghost-server -n 50`

### Watchdog timeout (systemd restarts Ghost)

Ghost pings systemd every 60s. If it misses two pings (120s), systemd restarts it.

Causes:
- Server is stuck (deadlock) — check logs before the restart
- High CPU/memory causing delays — check `htop` during load
- Bug — capture logs and report

## Diagnostic Commands

```bash
# Server status
sudo systemctl status ghost-server

# Live server logs
sudo journalctl -u ghost-server -f

# Health metrics
curl -s http://127.0.0.1:9090/health | jq .

# Check TLS certificate
openssl s_client -connect YOUR_DOMAIN:443 </dev/null 2>/dev/null | openssl x509 -noout -dates -subject

# Check what outsiders see (should be fallback website)
curl -s https://YOUR_DOMAIN/

# Check firewall rules
sudo nft list ruleset

# Check listening ports
ss -tlnp | grep -E '443|80|8080'

# Caddy status
sudo systemctl status caddy
```
