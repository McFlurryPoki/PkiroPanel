#!/usr/bin/env python3
"""
TransetPanel Agent — 節點守護程序
WebSocket 連接面板，管理 realm 轉發 + shadowsocks-rust 落地 + 系統監控
"""

import asyncio
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from websockets.asyncio.client import connect
except ImportError:
    print("websockets not installed. Run: pip3 install websockets psutil")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────
CONF_PATH = Path("/etc/realm-panel/agent.conf")
LOG_FILE = Path("/var/log/realm-agent.log")
DATA_DIR = Path("/etc/realm-panel")

# Load config
if CONF_PATH.exists():
    with open(CONF_PATH) as f:
        config = json.load(f)
else:
    print("Config not found. Run install script first.")
    sys.exit(1)

NODE_ID = config["node_id"]
PANEL_WS = config["panel_ws"]
AUTH_TOKEN = config["auth_token"]

RECONNECT_DELAY = 10
STATUS_INTERVAL = 60  # seconds
MAX_RECONNECT_DELAY = 300

# ── Logging ────────────────────────────────────────────────────────────────

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ── Monitor ────────────────────────────────────────────────────────────────

class Monitor:
    """System resource monitoring."""

    @staticmethod
    def get_stats() -> dict:
        stats = {
            "cpu_percent": 0.0,
            "mem_percent": 0.0,
            "disk_percent": 0.0,
            "net_rx_bytes": 0,
            "net_tx_bytes": 0,
            "net_rx_speed": 0.0,
            "net_tx_speed": 0.0,
            "realm_status": "unknown",
            "ss_status": "unknown",
            "uptime_seconds": int(time.time() - psutil.boot_time()) if HAS_PSUTIL else 0,
        }
        if HAS_PSUTIL:
            stats["cpu_percent"] = round(psutil.cpu_percent(interval=1), 1)
            mem = psutil.virtual_memory()
            stats["mem_percent"] = round(mem.percent, 1)
            disk = psutil.disk_usage("/")
            stats["disk_percent"] = round(disk.percent, 1)
            net = psutil.net_io_counters()
            stats["net_rx_bytes"] = net.bytes_recv
            stats["net_tx_bytes"] = net.bytes_sent

        # Check realm status
        try:
            result = subprocess.run(["systemctl", "is-active", "realm"], capture_output=True, text=True, timeout=5)
            stats["realm_status"] = result.stdout.strip()
        except Exception:
            stats["realm_status"] = "error"

        # Check ss-rust status
        try:
            result = subprocess.run(["systemctl", "is-active", "ss-rust"], capture_output=True, text=True, timeout=5)
            stats["ss_status"] = result.stdout.strip()
        except Exception:
            stats["ss_status"] = "error"

        return stats


# ── Realm Manager ──────────────────────────────────────────────────────────

class RealmManager:
    """Manage realm forwarding daemon."""

    CONF_PATH = Path("/etc/realm-panel/realm.toml")
    SERVICE = "realm"

    @staticmethod
    def generate_config(forwards: list) -> str:
        """Generate realm TOML config from forward rules."""
        lines = ["[log]", 'level = "warn"', 'output = "/var/log/realm.log"', ""]
        lines.append("[network]")
        lines.append('no_tcp = false')
        lines.append('use_udp = true')
        lines.append('udp_idle_timeout = "60s"')
        lines.append("")

        for i, fwd in enumerate(forwards):
            network = f"endpoint_{i}"
            lines.append(f"[[endpoints]]")
            lines.append(f'listen = "{fwd["listen_addr"]}"')
            lines.append(f'remote = "{fwd["remote_addr"]}"')

            # TLS support
            tls_mode = fwd.get("tls_mode", "none")
            if tls_mode in ("tls", "mtls"):
                lines.append(f'remote_tls = "{tls_mode}"')
                if fwd.get("cert_path"):
                    lines.append(f'cert = "{fwd["cert_path"]}"')
                if fwd.get("key_path"):
                    lines.append(f'key = "{fwd["key_path"]}"')
                if tls_mode == "mtls" and fwd.get("ca_path"):
                    lines.append(f'ca = "{fwd["ca_path"]}"')

            # Rate limit
            rate = fwd.get("rate_limit", 0)
            if rate > 0:
                lines.append(f'rate_limit = "{rate}KB"')

            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def start():
        subprocess.run(["systemctl", "start", RealmManager.SERVICE], check=False)

    @staticmethod
    def stop():
        subprocess.run(["systemctl", "stop", RealmManager.SERVICE], check=False)

    @staticmethod
    def restart():
        subprocess.run(["systemctl", "restart", RealmManager.SERVICE], check=False)

    @staticmethod
    def sync_config(forwards: list):
        """Write config and reload realm."""
        config_toml = RealmManager.generate_config(forwards)
        RealmManager.CONF_PATH.write_text(config_toml)
        RealmManager.restart()
        return {"ok": True, "forwards": len(forwards)}


# ── SS Manager ─────────────────────────────────────────────────────────────

class SSManager:
    """Manage shadowsocks-rust daemon."""

    CONF_PATH = Path("/etc/realm-panel/ss-rust.json")
    SERVICE = "ss-rust"

    @staticmethod
    def generate_config(ss_nodes: list) -> str:
        """Generate ss-rust JSON config."""
        servers = []
        for ss in ss_nodes:
            servers.append({
                "server": "0.0.0.0",
                "server_port": ss["port"],
                "method": ss.get("method", "2022-blake3-chacha20-poly1305"),
                "password": ss["password"],
            })
        config = {"servers": servers}
        return json.dumps(config, indent=2)

    @staticmethod
    def start():
        subprocess.run(["systemctl", "start", SSManager.SERVICE], check=False)

    @staticmethod
    def stop():
        subprocess.run(["systemctl", "stop", SSManager.SERVICE], check=False)

    @staticmethod
    def restart():
        subprocess.run(["systemctl", "restart", SSManager.SERVICE], check=False)

    @staticmethod
    def sync_config(ss_nodes: list):
        """Write config and reload ss-rust."""
        config_json = SSManager.generate_config(ss_nodes)
        SSManager.CONF_PATH.write_text(config_json)
        SSManager.restart()
        return {"ok": True, "ss_nodes": len(ss_nodes)}


# ── Command Handler ────────────────────────────────────────────────────────

async def handle_command(cmd: dict) -> dict:
    """Dispatch commands from panel."""
    action = cmd.get("action", "")
    params = cmd.get("params", {})

    try:
        if action == "realm.sync":
            forwards = params.get("forwards", [params.get("forward")] if params.get("forward") else [])
            return RealmManager.sync_config(forwards)

        elif action == "realm.start":
            RealmManager.start()
            return {"ok": True}

        elif action == "realm.stop":
            RealmManager.stop()
            return {"ok": True}

        elif action == "realm.restart":
            RealmManager.restart()
            return {"ok": True}

        elif action == "ss.sync":
            ss_nodes = params.get("ss_nodes", [params.get("ss_node")] if params.get("ss_node") else [])
            return SSManager.sync_config(ss_nodes)

        elif action == "ss.start":
            SSManager.start()
            return {"ok": True}

        elif action == "ss.stop":
            SSManager.stop()
            return {"ok": True}

        elif action == "ss.restart":
            SSManager.restart()
            return {"ok": True}

        elif action == "shell":
            cmd_str = params.get("command", "")
            timeout = params.get("timeout", 30)
            proc = await asyncio.create_subprocess_shell(
                cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return {"error": "timeout"}

            def safe_decode(data):
                for enc in ("utf-8", "gbk"):
                    try:
                        return data.decode(enc)
                    except (UnicodeDecodeError, LookupError):
                        continue
                return data.decode("utf-8", errors="replace")

            return {
                "exit_code": proc.returncode or 0,
                "stdout": safe_decode(stdout)[:50000],
                "stderr": safe_decode(stderr)[:5000],
            }

        elif action == "status":
            return Monitor.get_stats()

        else:
            return {"error": f"unknown action: {action}"}

    except Exception as e:
        return {"error": str(e)}


# ── Main Agent ─────────────────────────────────────────────────────────────

async def status_reporter(ws):
    """Periodically send status reports to panel."""
    while True:
        await asyncio.sleep(STATUS_INTERVAL)
        try:
            stats = Monitor.get_stats()
            await ws.send(json.dumps({
                "type": "status_report",
                "node_id": NODE_ID,
                "stats": stats,
            }))
        except Exception:
            break


async def agent_loop():
    """Main agent loop with reconnection."""
    reconnect_delay = RECONNECT_DELAY

    while True:
        try:
            log(f"Connecting to panel: {PANEL_WS}")
            async with connect(PANEL_WS, ping_interval=30, ping_timeout=15,
                               max_size=5 * 1024 * 1024) as ws:

                # Authenticate
                await ws.send(json.dumps({
                    "type": "auth",
                    "node_id": NODE_ID,
                    "token": AUTH_TOKEN,
                    "agent": {
                        "version": "1.0.0",
                        "os": f"{platform.system()} {platform.release()}",
                        "hostname": socket.gethostname(),
                    }
                }))
                resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                if resp.get("type") != "auth_ok":
                    log(f"Auth failed: {resp}")
                    await asyncio.sleep(30)
                    continue

                log("Connected to panel")
                reconnect_delay = RECONNECT_DELAY

                # Start status reporter in background
                reporter_task = asyncio.create_task(status_reporter(ws))

                # Command loop
                try:
                    async for raw in ws:
                        try:
                            msg = json.loads(raw)
                        except json.JSONDecodeError:
                            continue

                        if msg.get("type") == "cmd":
                            cmd_id = msg.get("id", "")
                            action = msg.get("action", "")
                            log(f"CMD [{cmd_id}]: {action}")
                            result = await handle_command(msg)
                            await ws.send(json.dumps({
                                "type": "result",
                                "id": cmd_id,
                                "data": result,
                            }))
                finally:
                    reporter_task.cancel()
                    try:
                        await reporter_task
                    except asyncio.CancelledError:
                        pass

        except (OSError, asyncio.TimeoutError, ConnectionError) as e:
            log(f"Connection lost: {e}")
        except Exception as e:
            log(f"Error: {e}")

        reconnect_delay = min(reconnect_delay * 1.5, MAX_RECONNECT_DELAY)
        log(f"Reconnecting in {int(reconnect_delay)}s...")
        await asyncio.sleep(reconnect_delay)


# ── Entry ──────────────────────────────────────────────────────────────────

def main():
    log("=== TransetPanel Agent v1.0 ===")
    log(f"Node ID: {NODE_ID}")
    log(f"Panel: {PANEL_WS}")

    # Ensure config directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Write PID file
    (DATA_DIR / "agent.pid").write_text(str(os.getpid()))

    asyncio.run(agent_loop())


if __name__ == "__main__":
    main()
