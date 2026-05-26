#!/bin/bash
# TransetPanel — 一鍵安裝腳本 (在有 SSH 的節點上手動執行)
# Usage: chmod +x install.sh && sudo ./install.sh

set -e

PANEL_URL="${1:-http://your-panel:32100}"
NODE_ID="${2:-}"
AUTH_TOKEN="${3:-}"

if [ -z "$NODE_ID" ] || [ -z "$AUTH_TOKEN" ]; then
    echo "Usage: $0 <PANEL_URL> <NODE_ID> <AUTH_TOKEN>"
    echo "Example: $0 http://1.2.3.4:32100 node-abc123 mysecrettoken"
    exit 1
fi

echo "============================================"
echo "  TransetPanel Agent Installer"
echo "============================================"
echo "Panel:  $PANEL_URL"
echo "Node:   $NODE_ID"
echo ""

# 1. Install system deps
echo "[1/5] Installing system packages..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip curl tar xz-utils
elif command -v yum &>/dev/null; then
    yum install -y -q python3 python3-pip curl tar xz
else
    echo "Unsupported package manager. Install python3, pip, curl manually."
    exit 1
fi

# 2. Install Python deps
echo "[2/5] Installing Python dependencies..."
pip3 install -q --break-system-packages websockets psutil

# 3. Install realm
echo "[3/5] Installing realm..."
REALM_VER=$(curl -s https://api.github.com/repos/zhboner/realm/releases/latest | grep tag_name | cut -d'"' -f4)
if [ -z "$REALM_VER" ]; then
    REALM_VER="v2.6.3"
fi
ARCH=$(uname -m)
case $ARCH in
    x86_64) REALM_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64) REALM_ARCH="aarch64-unknown-linux-gnu" ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
REALM_URL="https://github.com/zhboner/realm/releases/download/${REALM_VER}/realm-${REALM_ARCH}.tar.gz"
curl -sL "$REALM_URL" -o /tmp/realm.tar.gz
tar xzf /tmp/realm.tar.gz -C /usr/local/bin/
chmod +x /usr/local/bin/realm
rm /tmp/realm.tar.gz
echo "       realm $REALM_VER installed"

# 4. Install shadowsocks-rust
echo "[4/5] Installing shadowsocks-rust..."
SS_VER=$(curl -s https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | grep tag_name | cut -d'"' -f4)
if [ -z "$SS_VER" ]; then
    SS_VER="v1.24.0"
fi
case $ARCH in
    x86_64) SS_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64) SS_ARCH="aarch64-unknown-linux-gnu" ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
SS_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SS_VER}/shadowsocks-${SS_VER}.${SS_ARCH}.tar.xz"
curl -sL "$SS_URL" -o /tmp/ss.tar.xz
tar xJf /tmp/ss.tar.xz -C /usr/local/bin/
chmod +x /usr/local/bin/ss*
rm /tmp/ss.tar.xz
echo "       shadowsocks-rust $SS_VER installed"

# 5. Install agent
echo "[5/5] Installing agent..."
mkdir -p /etc/realm-panel /var/log

# Download config
curl -s "${PANEL_URL}/agent/config?node=${NODE_ID}&token=${AUTH_TOKEN}" -o /etc/realm-panel/agent.conf
echo "       Config downloaded"

# Download agent
curl -s "${PANEL_URL}/agent/agent.py" -o /usr/local/bin/realm-agent.py
chmod +x /usr/local/bin/realm-agent.py
echo "       Agent downloaded"

# Create realm service
cat > /etc/systemd/system/realm.service << 'UNIT'
[Unit]
Description=Realm Forwarding Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/realm-panel/realm.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# Create ss-rust service
cat > /etc/systemd/system/ss-rust.service << 'UNIT'
[Unit]
Description=Shadowsocks-rust Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c /etc/realm-panel/ss-rust.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# Create agent service
cat > /etc/systemd/system/realm-agent.service << 'UNIT'
[Unit]
Description=TransetPanel Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/realm-agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload 2>/dev/null
if systemctl enable --now realm-agent 2>/dev/null; then
    echo "       Agent service started (systemd)"
else
    echo "       systemd not available, using nohup fallback..."
    nohup /usr/bin/python3 /usr/local/bin/realm-agent.py > /var/log/realm-agent.log 2>&1 &
    echo $! > /etc/realm-panel/agent.pid
    disown
    echo "       Agent started (PID $(cat /etc/realm-panel/agent.pid))"
fi

echo ""
echo "============================================"
echo "  Installation Complete!"
echo "============================================"
echo "  realm:     systemctl status realm"
echo "  ss-rust:   systemctl status ss-rust"
echo "  agent:     systemctl status realm-agent"
echo "  logs:      journalctl -u realm-agent -f"
