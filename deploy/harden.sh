#!/bin/bash
set -euo pipefail

echo "=== Ghost Server Security Hardening ==="

# Create ghost system user if not exists
if ! id ghost &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin ghost
    echo "Created ghost system user"
fi

# Create directories
mkdir -p /var/lib/ghost
mkdir -p /etc/ghost

# Set ownership
chown ghost:ghost /var/lib/ghost
chown -R ghost:ghost /etc/ghost

# Copy updated service file
cp /tmp/ghost-server.service /etc/systemd/system/ghost-server.service

# Set binary capability (alternative to AmbientCapabilities)
setcap 'cap_net_bind_service=+ep' /usr/local/bin/ghost-server || true

# Reload systemd
systemctl daemon-reload

echo "=== Hardening complete ==="
echo "Run: systemctl restart ghost-server"
echo "Verify: systemctl status ghost-server"
echo "Verify: journalctl -u ghost-server -n 20"
