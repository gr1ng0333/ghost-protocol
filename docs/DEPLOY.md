# Server Deployment Guide

## Prerequisites

- VPS running Ubuntu 22.04+ (1+ vCPU, 1+ GB RAM)
- Domain with A record pointing to VPS IP
- Go 1.22+ (build machine)

## 1. Generate Keys

On your local machine:

```bash
go run ./cmd/ghost-keygen
```

Output:

```
=== Ghost Key Pairs ===

--- Server config (server.yaml) ---
auth:
  server_public_key: "<server_public_key_hex>"
  server_private_key: "<server_private_key_hex>"
  client_public_key: "<client_public_key_hex>"

--- Client config (client.yaml) ---
auth:
  server_public_key: "<server_public_key_hex>"
  client_private_key: "<client_private_key_hex>"
```

Save the full output. You'll paste the relevant sections into each config file.

## 2. Build Server

```bash
GOOS=linux GOARCH=amd64 go build -o ghost-server-linux ./cmd/ghost-server
```

## 3. Upload to VPS

```bash
scp ghost-server-linux user@YOUR_SERVER_IP:/tmp/ghost-server
scp configs/server.example.yaml user@YOUR_SERVER_IP:/tmp/server.yaml
scp profiles/chrome_browsing.json user@YOUR_SERVER_IP:/tmp/
scp -r deploy/ user@YOUR_SERVER_IP:/tmp/deploy/
```

## 4. Create System User

SSH into the VPS:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ghost
sudo mkdir -p /etc/ghost/profiles /var/lib/ghost/certs /var/log/ghost
sudo mv /tmp/ghost-server /usr/local/bin/ghost-server
sudo chmod +x /usr/local/bin/ghost-server
sudo mv /tmp/server.yaml /etc/ghost/server.yaml
sudo mv /tmp/chrome_browsing.json /etc/ghost/profiles/
sudo chown -R ghost:ghost /etc/ghost /var/lib/ghost /var/log/ghost
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/ghost-server
```

## 5. Server Configuration

Edit `/etc/ghost/server.yaml`:

```yaml
# Address to listen on (443 for HTTPS)
listen: ":443"

# Your domain (must resolve to this server)
domain: "YOUR_DOMAIN"

tls:
  # true = automatic Let's Encrypt certificates
  auto_cert: true
  # Email for Let's Encrypt registration (optional but recommended)
  email: "you@example.com"
  # Directory for certificate cache
  cache_dir: "/var/lib/ghost/certs"

  # For manual certificates (set auto_cert: false):
  # cert_file: "/etc/ghost/cert.pem"
  # key_file: "/etc/ghost/key.pem"

auth:
  # Paste from ghost-keygen output (server section)
  server_public_key: "<server_public_key_hex>"
  server_private_key: "<server_private_key_hex>"
  client_public_key: "<client_public_key_hex>"

backend:
  # Allowed destination ports (empty = all allowed)
  allowed_ports: []

shaping:
  # Default shaping mode: "stealth", "balanced", or "performance"
  default_mode: "balanced"
  # Traffic profile for padding/timing distributions
  profile_path: "/etc/ghost/profiles/chrome_browsing.json"
  # Allow client to request mode changes
  auto_mode: true

fallback:
  # Caddy listens here, Ghost proxies non-Ghost traffic to it
  addr: "127.0.0.1:8080"
  use_caddy: true

sessions:
  # Maximum concurrent client sessions
  max_sessions: 5
  # Disconnect idle sessions after this many seconds
  idle_timeout_sec: 300

log:
  level: "info"
  file: "stdout"
```

## 6. Caddy Fallback

Caddy serves a real website to non-Ghost connections, making the server indistinguishable from a legitimate web server under active probing.

Install Caddy:

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudware.com/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudware.com/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

Deploy Caddyfile:

```bash
sudo cp /tmp/deploy/Caddyfile /etc/caddy/Caddyfile
```

The Caddyfile configures Caddy on port 8080 as a static file server:

```caddyfile
:8080 {
    root * /var/www/ghost-fallback
    file_server
    encode gzip

    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
    }

    log {
        output file /var/log/caddy/access.log
    }
}
```

Deploy the fallback website:

```bash
sudo mkdir -p /var/www/ghost-fallback /var/log/caddy
sudo cp -r /tmp/deploy/website/* /var/www/ghost-fallback/
sudo systemctl enable --now caddy
```

## 7. systemd Service

```bash
sudo cp /tmp/deploy/ghost-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ghost-server
```

The service file:

```ini
[Unit]
Description=Ghost Protocol Server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/ghost-server /etc/ghost/server.yaml
Restart=always
RestartSec=5
WatchdogSec=120

User=ghost
Group=ghost
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ReadWritePaths=/etc/ghost /var/lib/ghost /var/log/ghost
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

StandardOutput=journal
StandardError=journal
SyslogIdentifier=ghost-server

[Install]
WantedBy=multi-user.target
```

Key points:
- `Type=notify` — Ghost signals systemd when it's ready to accept connections
- `WatchdogSec=120` — Ghost pings systemd every 60s; systemd restarts if no ping for 120s
- `CAP_NET_BIND_SERVICE` — allows binding port 443 without root
- Filesystem restrictions limit Ghost to its own directories

## 8. Firewall (nftables)

```bash
sudo apt install -y nftables
sudo cp /tmp/deploy/nftables.conf /etc/nftables.conf
sudo systemctl enable --now nftables
```

Rules (allow only SSH, HTTP for ACME, and HTTPS):

```
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        tcp dport 22 accept
        tcp dport 80 accept
        tcp dport 443 accept
        icmp type echo-request accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

## 9. Sysctl Tuning

```bash
sudo cp /tmp/deploy/99-ghost.conf /etc/sysctl.d/99-ghost.conf
sudo sysctl --system
```

Settings applied:

```
net.core.somaxconn = 4096
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.ip_forward = 1
```

## 10. Verify Deployment

Check service status:

```bash
sudo systemctl status ghost-server
sudo journalctl -u ghost-server -f
```

Check health endpoint (from the server itself):

```bash
curl -s http://127.0.0.1:9090/health | jq .
```

Expected output includes `active_sessions`, `uptime`, `bytes_sent`, `bytes_recv`.

Test the fallback site from outside:

```bash
curl -s https://YOUR_DOMAIN/
```

Should return the fallback website HTML, confirming TLS works and non-Ghost connections are served normally.

## 11. Certificate Management

**Automatic (recommended):** Set `tls.auto_cert: true` and `tls.email`. Ghost handles Let's Encrypt HTTP-01 challenges on port 80 and auto-renews certificates. Requires port 80 open in firewall and domain resolving to the VPS.

**Manual:** Set `tls.auto_cert: false` and provide `tls.cert_file` / `tls.key_file` paths. Ghost watches these files and reloads on change. Use this when you manage certs externally (e.g., Cloudflare origin certs).

**Self-signed (testing only):** Generate with `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`. Client must trust the CA or you accept the risk of no server verification.
