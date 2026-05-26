#!/bin/bash
# TransetPanel — 一鍵安裝腳本（中國大陸版）
# 所有組件從面板鏡像站下載，無需訪問 GitHub
# Usage: chmod +x install-cn.sh && sudo ./install-cn.sh
#
# 與普通版差異：
#   realm / shadowsocks-rust → 面板內建鏡像，不走 GitHub

set -e

PANEL_URL="${1:-http://your-panel:32100}"
NODE_ID="${2:-}"
AUTH_TOKEN="${3:-}"

if [ -z "$NODE_ID" ] || [ -z "$AUTH_TOKEN" ]; then
    echo "Usage: $0 <PANEL_URL> <NODE_ID> <AUTH_TOKEN>"
    echo "Example: $0 https://transet.yumenashyi.com:443 node-abc123 mysecrettoken"
    exit 1
fi

echo "============================================"
echo "  TransetPanel Agent Installer (CN Mirror)"
echo "============================================"
echo "Panel:  $PANEL_URL"
echo "Node:   $NODE_ID"
echo ""

# ── Arch mapping ────────────────────────────────────────────────────────────
ARCH=$(uname -m)
case $ARCH in
    x86_64)  REALM_BIN="realm-x86_64.tar.gz"
             SS_BIN="ssrust-x86_64.tar.xz" ;;
    aarch64) REALM_BIN="realm-aarch64.tar.gz"
             SS_BIN="ssrust-aarch64.tar.xz" ;;
    *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# ── 1. System packages ──────────────────────────────────────────────────────
echo "[1/5] Installing system packages..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip curl tar xz-utils
elif command -v yum &>/dev/null; then
    yum install -y -q python3 python3-pip curl tar xz
elif command -v apk &>/dev/null; then
    apk add --no-cache python3 py3-pip curl tar xz
else
    echo "Unsupported package manager. Install python3, pip, curl, tar manually."
    exit 1
fi

# ── 2. Python deps ──────────────────────────────────────────────────────────
echo "[2/5] Installing Python dependencies..."
pip3 install -q --break-system-packages websockets psutil 2>/dev/null || \
pip3 install -q websockets psutil 2>/dev/null || {
    echo "pip3 install failed, trying with --user..."
    pip3 install -q --user websockets psutil
}

# ── 3. Install realm (from panel mirror) ────────────────────────────────────
echo "[3/5] Installing realm (from panel mirror)..."
echo "       → ${PANEL_URL}/agent/bin/${REALM_BIN}"
curl -sL "${PANEL_URL}/agent/bin/${REALM_BIN}" -o /tmp/realm.tar.gz
tar xzf /tmp/realm.tar.gz -C /usr/local/bin/
chmod +x /usr/local/bin/realm
rm /tmp/realm.tar.gz
echo "       realm installed"

# ── 4. Install shadowsocks-rust (from panel mirror) ─────────────────────────
echo "[4/5] Installing shadowsocks-rust (from panel mirror)..."
echo "       → ${PANEL_URL}/agent/bin/${SS_BIN}"
curl -sL "${PANEL_URL}/agent/bin/${SS_BIN}" -o /tmp/ss.tar.xz
tar xJf /tmp/ss.tar.xz -C /usr/local/bin/
chmod +x /usr/local/bin/ss*
rm /tmp/ss.tar.xz
echo "       shadowsocks-rust installed"

# ── 5. Install agent ────────────────────────────────────────────────────────
echo "[5/5] Installing agent..."
mkdir -p /etc/realm-panel /var/log

# Download config
curl -s "${PANEL_URL}/agent/config?node=${NODE_ID}&token=${AUTH_TOKEN}" -o /etc/realm-panel/agent.conf
echo "       Config downloaded"

# Download agent
curl -s "${PANEL_URL}/agent/agent.py" -o /usr/local/bin/realm-agent.py
chmod +x /usr/local/bin/realm-agent.py
echo "       Agent downloaded"

# ── systemd services ────────────────────────────────────────────────────────
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
echo "  Installation Complete! (CN Mirror)"
echo "============================================"
echo "  realm:     systemctl status realm"
echo "  ss-rust:   systemctl status ss-rust"
echo "  agent:     systemctl status realm-agent"
echo "  logs:      journalctl -u realm-agent -f"
