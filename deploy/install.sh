#!/bin/bash
set -euo pipefail

# Ghost Server Deployment Script
# Run as root on the target server.
# Prerequisites: ghost-server binary and config files already uploaded.

GHOST_BIN="/usr/local/bin/ghost-server"
GHOST_CONFIG="/etc/ghost/server.yaml"
GHOST_LOG="/var/log/ghost"
GHOST_PROFILE_DIR="/etc/ghost/profiles"
WEBSITE_DIR="/var/www/ghost-fallback"

echo "=== Ghost Server Deployment ==="

# 1. Create directories
mkdir -p /etc/ghost
mkdir -p "$GHOST_LOG"
mkdir -p "$GHOST_PROFILE_DIR"
mkdir -p "$WEBSITE_DIR"
mkdir -p /var/lib/ghost/certs
mkdir -p /var/log/caddy

# 2. Install system packages
apt-get update -qq
apt-get install -y -qq caddy nftables

# 3. Deploy firewall
cp /tmp/ghost-deploy/nftables.conf /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables

# 4. Deploy sysctl
cp /tmp/ghost-deploy/99-ghost.conf /etc/sysctl.d/99-ghost.conf
sysctl --system > /dev/null 2>&1

# 5. Deploy website
cp -r /tmp/ghost-deploy/website/* "$WEBSITE_DIR/"

# 6. Deploy Caddyfile
cp /tmp/ghost-deploy/Caddyfile /etc/caddy/Caddyfile
systemctl enable caddy
systemctl restart caddy

# 7. Deploy Ghost binary + config
cp /tmp/ghost-deploy/ghost-server "$GHOST_BIN"
chmod +x "$GHOST_BIN"

# 8. Deploy profiles
cp /tmp/ghost-deploy/profiles/* "$GHOST_PROFILE_DIR/" 2>/dev/null || true

# 9. Deploy systemd service
cp /tmp/ghost-deploy/ghost-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable ghost-server

# 10. Start/restart Ghost
systemctl restart ghost-server
sleep 2

# 11. Verify
echo ""
echo "=== Verification ==="
echo "Ghost server status:"
systemctl is-active ghost-server && echo "  Running" || echo "  NOT running"
echo "Caddy status:"
systemctl is-active caddy && echo "  Running" || echo "  NOT running"
echo "Firewall status:"
systemctl is-active nftables && echo "  Active" || echo "  NOT active"
echo ""
echo "Testing Caddy fallback (localhost:8080):"
curl -s -o /dev/null -w "  HTTP %{http_code}\n" http://localhost:8080/ || echo "  Failed"
echo ""
echo "Last 10 lines of Ghost log:"
tail -10 "$GHOST_LOG/server.log" 2>/dev/null || echo "  (no log yet)"
echo ""
echo "=== Deployment complete ==="
