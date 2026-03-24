"""VPS verification script for ghost-server deployment."""
import paramiko
import sys

host = '94.156.122.66'
user = 'root'
passwd = 'ImxbXNXHHmU3'

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(host, username=user, password=passwd)

def run(cmd, label=""):
    if label:
        print(f"\n=== {label} ===")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    if out.strip():
        print(out)
    if err.strip():
        print("STDERR:", err)
    return out

# Service status
run("systemctl is-active ghost-server", "Ghost Service")
run("systemctl is-active caddy", "Caddy Service")

# Ports
run("ss -tlnp | grep -E ':(443|8080|80|22) '", "Listening Ports")

# Recent logs
run("journalctl -u ghost-server -n 20 --no-pager", "Recent Ghost Logs")

# HTTPS fallback test
https_test = (
    'python3 -c "'
    "import ssl, urllib.request; "
    "ctx = ssl.create_default_context(); "
    "ctx.check_hostname = False; "
    "ctx.verify_mode = ssl.CERT_NONE; "
    "resp = urllib.request.urlopen('https://localhost:443/', context=ctx, timeout=5); "
    "print(resp.read(500).decode('utf-8', errors='replace'))"
    '"'
)
run(https_test, "HTTPS Fallback Test (should show website HTML)")

# HTTP Caddy direct test
http_test = (
    'python3 -c "'
    "import urllib.request; "
    "resp = urllib.request.urlopen('http://localhost:8080/', timeout=5); "
    "print(resp.read(200).decode('utf-8', errors='replace'))"
    '"'
)
run(http_test, "HTTP Caddy Direct Test")

ssh.close()
print("\n=== Verification Complete ===")
