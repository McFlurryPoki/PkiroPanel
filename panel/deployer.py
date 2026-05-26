"""SSH deployer — remotely install agent + gost + sing-box on a node."""

import asyncio
import os
from asyncssh import connect, SSHClientConnection
from panel.crypto_utils import decrypt


PANEL_URL = os.environ.get("PANEL_URL", "http://localhost:32100")

CN_NODES = {"node-92c4c9f0", "node-9b0a75d1"}  # GZ, SZ — use China mirrors

INSTALL_SCRIPT = """#!/bin/bash
set -e

ARCH=$(uname -m)
case $ARCH in
    x86_64|amd64)   GOST_BIN="gost-linux-amd64.tar.gz";  SB_ARCH="amd64" ;;
    aarch64|arm64)  GOST_BIN="gost-linux-arm64.tar.gz"; SB_ARCH="arm64" ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# ── Determine mode from node type ──
# entry/transit → gost + WG (no sing-box)
# landing → sing-box (no gost, no WG)
INSTALL_GOST=true; INSTALL_WG=true; INSTALL_SB=false
if [ "{NODE_TYPE}" = "landing" ]; then
    INSTALL_GOST=false; INSTALL_WG=false; INSTALL_SB=true
fi

echo "[1/4] Installing system packages..."
PKGS="python3 python3-pip curl tar xz-utils"
if $INSTALL_WG; then PKGS="$PKGS wireguard-tools"; fi
apt-get update -qq && apt-get install -y -qq $PKGS > /dev/null 2>&1

echo "[2/4] Installing Python deps..."
pip3 install -q --break-system-packages websockets psutil > /dev/null 2>&1

if $INSTALL_GOST; then
    echo "[3/4] Installing gost..."
    curl -sL "{PANEL_URL}/agent/bin/$GOST_BIN" | tar xz -C /usr/local/bin/
    find /usr/local/bin/ -name 'gost*' -type f -exec chmod +x {{}} \\;
    echo "       gost installed"
fi

if $INSTALL_WG; then
    echo "       Configuring WireGuard..."
    mkdir -p /etc/wireguard
    if [ ! -f /etc/wireguard/privatekey ]; then
        wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
        chmod 600 /etc/wireguard/privatekey
    fi
    echo "       WireGuard keys generated"
fi

if $INSTALL_SB; then
    echo "[3/4] Installing sing-box..."
    curl -sL "{SB_DOWNLOAD_URL}" | tar xz -C /usr/local/bin/ --strip-components=1 "sing-box-1.10.7-linux-$SB_ARCH/sing-box"
    chmod +x /usr/local/bin/sing-box
    echo "       sing-box installed"
fi

echo "[4/4] Downloading agent..."
mkdir -p /etc/realm-panel
curl -s "{PANEL_URL}/agent/config?node={NODE_ID}&token={AUTH_TOKEN}" -o /etc/realm-panel/agent.conf
curl -s "{PANEL_URL}/agent/agent.py" -o /usr/local/bin/realm-agent.py

echo "       Setting up systemd services..."

# Cleanup old services
for svc in ss-rust realm; do
    if systemctl is-active $svc > /dev/null 2>&1; then
        systemctl stop $svc 2>/dev/null
        systemctl disable $svc 2>/dev/null
        rm -f /etc/systemd/system/$svc.service
        echo "       Old $svc service removed"
    fi
done
if systemctl is-active sing-box > /dev/null 2>&1 && ! $INSTALL_SB; then
    systemctl stop sing-box 2>/dev/null; systemctl disable sing-box 2>/dev/null
    rm -f /etc/systemd/system/sing-box.service
    echo "       sing-box removed (not needed on this node type)"
fi
rm -f /usr/local/bin/ssserver /usr/local/bin/sslocal /usr/local/bin/realm

# gost service
if $INSTALL_GOST; then
cat > /etc/systemd/system/gost.service << 'UNIT'
[Unit]
Description=GOST Forwarding Service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/gost -C /etc/realm-panel/gost.yml
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
fi

# WireGuard wg-quick template
if $INSTALL_WG; then
cat > /etc/systemd/system/wg-quick@.service << 'UNIT'
[Unit]
Description=WireGuard via wg-quick(8) for %I
After=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/wg-quick up %i
ExecStop=/usr/bin/wg-quick down %i
[Install]
WantedBy=multi-user.target
UNIT
fi

# sing-box service
if $INSTALL_SB; then
cat > /etc/systemd/system/sing-box.service << 'UNIT'
[Unit]
Description=Sing-box Proxy Service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/realm-panel/sing-box.json
Restart=always
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT
fi

# Agent service
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
$INSTALL_SB && systemctl enable sing-box 2>/dev/null

if systemctl restart realm-agent 2>/dev/null; then
    echo "       Agent restarted (systemd)"
else
    pkill -f realm-agent.py 2>/dev/null; sleep 1
    nohup /usr/bin/python3 /usr/local/bin/realm-agent.py > /var/log/realm-agent.log 2>&1 &
    echo $! > /etc/realm-panel/agent.pid; disown
    echo "       Agent started via nohup (PID $(cat /etc/realm-panel/agent.pid))"
fi
echo "DONE"
"""


class Deployer:
    """Handles SSH-based agent deployment to remote nodes."""

    def __init__(self):
        self.active_deployments: dict[str, asyncio.Queue] = {}  # node_id -> log queue

    async def deploy(self, node: dict) -> asyncio.Queue:
        """Deploy agent to a node. Returns an asyncio.Queue for log streaming."""
        node_id = node["id"]
        log_queue: asyncio.Queue = asyncio.Queue()
        self.active_deployments[node_id] = log_queue

        asyncio.create_task(self._do_deploy(node, log_queue))
        return log_queue

    async def _do_deploy(self, node: dict, log_queue: asyncio.Queue):
        try:
            password = decrypt(node["ssh_password"])
            host = node["host"]
            port = node.get("ssh_port", 22)
            username = node.get("ssh_user", "root")
            node_id = node["id"]

            await log_queue.put("Connecting via SSH...")
            async with connect(host, port=port, username=username,
                               password=password, known_hosts=None) as conn:
                await log_queue.put(f"Connected to {host}:{port}")

                script = INSTALL_SCRIPT.format(
                    PANEL_URL=PANEL_URL,
                    NODE_ID=node_id,
                    AUTH_TOKEN=os.environ.get("SECRET_KEY", "default")[:32],
                    NODE_TYPE=node.get("type", ""),
                    SB_DOWNLOAD_URL=(
                        "https://ghproxy.com/https://github.com/SagerNet/sing-box/releases/download/v1.10.7/sing-box-1.10.7-linux-$SB_ARCH.tar.gz"
                        if node_id in CN_NODES else
                        "https://github.com/SagerNet/sing-box/releases/download/v1.10.7/sing-box-1.10.7-linux-$SB_ARCH.tar.gz"
                    ),
                )

                await log_queue.put("Running install script...")
                result = await conn.run(f"bash -s << 'SCRIPT'\n{script}\nSCRIPT", check=False)
                stdout = result.stdout or ""
                stderr = result.stderr or ""

                for line in stdout.split("\n"):
                    if line.strip():
                        await log_queue.put(line.strip())

                if result.exit_status == 0:
                    await log_queue.put("__SUCCESS__")
                else:
                    await log_queue.put(f"__ERROR__: exit_code={result.exit_status}")
                    if stderr:
                        await log_queue.put(stderr[:500])

        except Exception as e:
            await log_queue.put(f"__ERROR__: {e}")
        finally:
            await log_queue.put("__CLOSE__")

    def get_log_queue(self, node_id: str) -> asyncio.Queue | None:
        return self.active_deployments.get(node_id)

    def remove_deployment(self, node_id: str):
        self.active_deployments.pop(node_id, None)


deployer = Deployer()
