"""CRUD operations for all models."""

import json
import uuid
import time
from panel.database import get_db


# ── Nodes ─────────────────────────────────────────────────────────────────

async def list_nodes():
    db = await get_db()
    cursor = await db.execute(
        "SELECT n.*, ns.cpu_percent, ns.mem_percent, ns.net_rx_speed, ns.net_tx_speed, "
        "ns.realm_status, ns.ss_status, ns.uptime_seconds, ns.recorded_at as stats_at "
        "FROM nodes n LEFT JOIN ("
        "  SELECT node_id, cpu_percent, mem_percent, net_rx_speed, net_tx_speed, "
        "  realm_status, ss_status, uptime_seconds, recorded_at, "
        "  ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY id DESC) as rn "
        "  FROM node_stats"
        ") ns ON n.id = ns.node_id AND ns.rn = 1 "
        "ORDER BY n.created_at DESC"
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_node(node_id: str):
    db = await get_db()
    cursor = await db.execute("SELECT * FROM nodes WHERE id = ?", (node_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def create_node(data: dict):
    db = await get_db()
    node_id = data.get("id") or f"node-{uuid.uuid4().hex[:8]}"
    await db.execute(
        """INSERT INTO nodes (id, name, type, host, entry_ip, port_start, port_end,
           ssh_port, ssh_user, ssh_password, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (node_id, data["name"], data.get("type", "transit"), data["host"],
         data.get("entry_ip"), data.get("port_start"), data.get("port_end"),
         data.get("ssh_port", 22), data.get("ssh_user", "root"),
         data.get("ssh_password"), time.time())
    )
    await db.commit()
    return await get_node(node_id)


async def update_node(node_id: str, data: dict):
    db = await get_db()
    fields = []
    values = []
    allowed = ["name", "type", "host", "entry_ip", "port_start", "port_end",
               "ssh_port", "ssh_user", "ssh_password", "agent_port", "agent_deployed",
               "status", "agent_version", "os_info", "last_seen",
               "wg_private_key", "wg_public_key"]
    for f in allowed:
        if f in data:
            fields.append(f"{f} = ?")
            values.append(data[f])
    if fields:
        values.append(node_id)
        await db.execute(f"UPDATE nodes SET {', '.join(fields)} WHERE id = ?", values)
        await db.commit()
    return await get_node(node_id)


async def delete_node(node_id: str):
    db = await get_db()
    await db.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    await db.commit()


# ── Node Stats ────────────────────────────────────────────────────────────

async def save_node_stats(node_id: str, stats: dict):
    db = await get_db()
    await db.execute(
        """INSERT INTO node_stats (node_id, cpu_percent, mem_percent, disk_percent,
           net_rx_bytes, net_tx_bytes, net_rx_speed, net_tx_speed,
           realm_status, ss_status, uptime_seconds, recorded_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (node_id, stats.get("cpu_percent"), stats.get("mem_percent"),
         stats.get("disk_percent"), stats.get("net_rx_bytes"),
         stats.get("net_tx_bytes"), stats.get("net_rx_speed"),
         stats.get("net_tx_speed"), stats.get("realm_status"),
         stats.get("ss_status"), stats.get("uptime_seconds"), time.time())
    )
    await db.commit()


async def get_node_stats(node_id: str, hours: int = 24):
    db = await get_db()
    since = time.time() - hours * 3600
    cursor = await db.execute(
        "SELECT * FROM node_stats WHERE node_id = ? AND recorded_at > ? ORDER BY recorded_at",
        (node_id, since)
    )
    return [dict(r) for r in await cursor.fetchall()]


# ── Forwards ──────────────────────────────────────────────────────────────

async def list_forwards(node_id: str = None):
    db = await get_db()
    if node_id:
        cursor = await db.execute(
            "SELECT * FROM forwards WHERE node_id = ? ORDER BY created_at DESC", (node_id,))
    else:
        cursor = await db.execute("SELECT * FROM forwards ORDER BY created_at DESC")
    return [dict(r) for r in await cursor.fetchall()]


async def create_forward(data: dict):
    db = await get_db()
    fwd_id = data.get("id") or f"fwd-{uuid.uuid4().hex[:8]}"
    await db.execute(
        """INSERT INTO forwards (id, node_id, listen_addr, remote_addr, tls_mode,
           cert_path, key_path, ca_path, rate_limit, enabled, forward_type, tunnel_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (fwd_id, data["node_id"], data["listen_addr"], data["remote_addr"],
         data.get("tls_mode", "none"), data.get("cert_path"), data.get("key_path"),
         data.get("ca_path"), data.get("rate_limit", 0),
         data.get("enabled", 1), data.get("forward_type", "port"),
         data.get("tunnel_id"), time.time())
    )
    await db.commit()
    cursor = await db.execute("SELECT * FROM forwards WHERE id = ?", (fwd_id,))
    return dict(await cursor.fetchone())


async def create_tunnel_forwards(entry_node_id: str, exit_node_id: str, landing_addr: str,
                                  listen_port: int, tunnel_port: int,
                                  tls_mode: str = "tls", rate_limit: int = 0) -> list[dict]:
    from panel import models as m
    import ipaddress
    tunnel_id = f"tun-{uuid.uuid4().hex[:8]}"

    entry_node = await m.get_node(entry_node_id)
    exit_node = await m.get_node(exit_node_id)

    if not all([entry_node, exit_node]):
        raise ValueError("One or more nodes not found")

    if tls_mode == "wg":
        # ── WireGuard mode ──────────────────────────────────────────────
        # Ensure both nodes have WG keys (generate via Python, no wg CLI needed)
        import base64
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        except ImportError:
            raise ValueError("cryptography library required for WG key generation")

        for node in [entry_node, exit_node]:
            if not node.get("wg_private_key") or not node.get("wg_public_key"):
                priv_key = X25519PrivateKey.generate()
                priv_bytes = priv_key.private_bytes_raw()
                pub_bytes = priv_key.public_key().public_bytes_raw()
                priv = base64.b64encode(priv_bytes).decode()
                pub = base64.b64encode(pub_bytes).decode()
                await m.update_node(node["id"], {"wg_private_key": priv, "wg_public_key": pub})
                node["wg_private_key"] = priv
                node["wg_public_key"] = pub

        # Assign WG IPs: allocate next /30 from 10.99.x.x pool
        db = await get_db()
        cursor = await db.execute(
            "SELECT MAX(entry_wg_ip) as max_ip FROM wg_tunnels")
        row = await cursor.fetchone()
        last_ip = row["max_ip"] if row and row["max_ip"] else "10.99.0.1"
        net = ipaddress.IPv4Network("10.99.0.0/16")
        last = ipaddress.IPv4Address(last_ip)
        # Find next available /30
        next_net = ipaddress.IPv4Network(f"{last}/{30}", strict=False)
        next_net = ipaddress.IPv4Network(f"{next_net.network_address + 4}/{30}", strict=False)
        if next_net.network_address >= ipaddress.IPv4Address("10.99.255.252"):
            raise ValueError("WG IP pool exhausted")

        entry_ip = str(next_net.network_address + 1)
        exit_ip = str(next_net.network_address + 2)
        wg_port = 51820  # WireGuard protocol port (NOT gost forwarding port)

        # Record wg_tunnel
        wg_id = f"wg-{uuid.uuid4().hex[:8]}"
        await db.execute(
            "INSERT INTO wg_tunnels (id, entry_node_id, exit_node_id, tunnel_ip_cidr, entry_wg_ip, exit_wg_ip, listen_port, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (wg_id, entry_node_id, exit_node_id, str(next_net), entry_ip, exit_ip, wg_port, time.time()))
        await db.commit()

        # Forward 1: entry listens on public → forwards via WG to exit
        fwd1 = await create_forward({
            "node_id": entry_node_id,
            "listen_addr": f"0.0.0.0:{listen_port}",
            "remote_addr": f"{exit_ip}:{tunnel_port}",
            "tls_mode": "wg",
            "rate_limit": rate_limit,
            "forward_type": "tunnel",
            "tunnel_id": tunnel_id,
        })

        # Forward 2: exit listens on WG IP → forwards to landing
        fwd2 = await create_forward({
            "node_id": exit_node_id,
            "listen_addr": f"{exit_ip}:{tunnel_port}",
            "remote_addr": landing_addr,
            "tls_mode": "none",
            "rate_limit": rate_limit,
            "forward_type": "tunnel",
            "tunnel_id": tunnel_id,
        })

        return [fwd1, fwd2]

    # ── TLS/mTLS mode (original logic) ─────────────────────────────────
    fwd1 = await create_forward({
        "node_id": entry_node_id,
        "listen_addr": f"0.0.0.0:{listen_port}",
        "remote_addr": f"{exit_node['host']}:{tunnel_port}",
        "tls_mode": tls_mode,
        "rate_limit": rate_limit,
        "forward_type": "tunnel",
        "tunnel_id": tunnel_id,
    })

    fwd2 = await create_forward({
        "node_id": exit_node_id,
        "listen_addr": f"0.0.0.0:{tunnel_port}",
        "remote_addr": landing_addr,
        "tls_mode": "none",
        "rate_limit": rate_limit,
        "forward_type": "tunnel",
        "tunnel_id": tunnel_id,
    })

    return [fwd1, fwd2]


# ── WireGuard helpers ─────────────────────────────────────────────────────

async def list_wg_tunnels(node_id: str = None) -> list[dict]:
    """List WG tunnels for a node (used by agent sync)."""
    db = await get_db()
    if node_id:
        cursor = await db.execute(
            "SELECT * FROM wg_tunnels WHERE entry_node_id = ? OR exit_node_id = ? ORDER BY created_at",
            (node_id, node_id))
    else:
        cursor = await db.execute("SELECT * FROM wg_tunnels ORDER BY created_at")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_wg_peers(node_id: str) -> list[dict]:
    """Get all WG peer info for a node: its own data plus all peer nodes.
    Returns list of peers with: public_key, endpoint, allowed_ips, wg_ip"""
    from panel import models as m
    tunnels = await list_wg_tunnels(node_id)
    node = await m.get_node(node_id)
    peers = []
    for t in tunnels:
        if t["entry_node_id"] == node_id:
            peer_node = await m.get_node(t["exit_node_id"])
            peers.append({
                "public_key": peer_node.get("wg_public_key", ""),
                "endpoint": f"{peer_node['host']}:{t['listen_port']}",
                "allowed_ips": f"{t['exit_wg_ip']}/32",
                "wg_ip": t["entry_wg_ip"],
            })
        elif t["exit_node_id"] == node_id:
            peer_node = await m.get_node(t["entry_node_id"])
            peers.append({
                "public_key": peer_node.get("wg_public_key", ""),
                "endpoint": f"{peer_node['host']}:{t['listen_port']}",
                "allowed_ips": f"{t['entry_wg_ip']}/32",
                "wg_ip": t["exit_wg_ip"],
            })
    return peers


async def update_forward(fwd_id: str, data: dict):
    db = await get_db()
    fields = []
    values = []
    allowed = ["listen_addr", "remote_addr", "tls_mode", "cert_path", "key_path",
               "ca_path", "rate_limit", "enabled"]
    for f in allowed:
        if f in data:
            fields.append(f"{f} = ?")
            values.append(data[f])
    if fields:
        values.append(fwd_id)
        await db.execute(f"UPDATE forwards SET {', '.join(fields)} WHERE id = ?", values)
        await db.commit()


async def delete_forward(fwd_id: str):
    db = await get_db()
    await db.execute("DELETE FROM forwards WHERE id = ?", (fwd_id,))
    await db.commit()


# ── SS Nodes ──────────────────────────────────────────────────────────────

async def list_ss_nodes(node_id: str = None):
    db = await get_db()
    if node_id:
        cursor = await db.execute(
            "SELECT * FROM ss_nodes WHERE node_id = ? ORDER BY created_at DESC", (node_id,))
    else:
        cursor = await db.execute("SELECT * FROM ss_nodes ORDER BY created_at DESC")
    return [dict(r) for r in await cursor.fetchall()]


async def create_ss_node(data: dict):
    db = await get_db()
    ss_id = data.get("id") or f"ss-{uuid.uuid4().hex[:8]}"
    await db.execute(
        """INSERT INTO ss_nodes (id, node_id, port, method, password, rate_limit, enabled, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ss_id, data["node_id"], data["port"],
         data.get("method", "2022-blake3-chacha20-poly1305"),
         data["password"], data.get("rate_limit", 0),
         data.get("enabled", 1), time.time())
    )
    await db.commit()
    cursor = await db.execute("SELECT * FROM ss_nodes WHERE id = ?", (ss_id,))
    return dict(await cursor.fetchone())


async def update_ss_node(ss_id: str, data: dict):
    db = await get_db()
    fields = []
    values = []
    allowed = ["port", "method", "password", "rate_limit", "enabled"]
    for f in allowed:
        if f in data:
            fields.append(f"{f} = ?")
            values.append(data[f])
    if fields:
        values.append(ss_id)
        await db.execute(f"UPDATE ss_nodes SET {', '.join(fields)} WHERE id = ?", values)
        await db.commit()


async def delete_ss_node(ss_id: str):
    db = await get_db()
    await db.execute("DELETE FROM ss_nodes WHERE id = ?", (ss_id,))
    await db.commit()


# ── Inbounds (sing-box) ────────────────────────────────────────────────────

async def list_inbounds(node_id: str = None) -> list[dict]:
    db = await get_db()
    if node_id:
        cursor = await db.execute(
            "SELECT * FROM inbounds WHERE node_id = ? ORDER BY port", (node_id,))
    else:
        cursor = await db.execute("SELECT * FROM inbounds ORDER BY port")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_inbound(inbound_id: str) -> dict:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM inbounds WHERE id = ?", (inbound_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def create_inbound(data: dict) -> dict:
    db = await get_db()
    import uuid, json
    inbound_id = data.get("id") or f"in-{uuid.uuid4().hex[:8]}"
    tag = data.get("tag") or f"{data.get('protocol','ss')}-{data.get('port','?')}"
    await db.execute(
        "INSERT INTO inbounds (id, node_id, protocol, tag, port, listen, settings, stream, rate_limit, enabled, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (inbound_id, data["node_id"], data.get("protocol", "shadowsocks"), tag,
         data["port"], data.get("listen", "0.0.0.0"),
         json.dumps(data.get("settings", {})),
         json.dumps(data.get("stream", {"network": "tcp"})),
         data.get("rate_limit", 0), data.get("enabled", 1), time.time()))
    await db.commit()
    return await get_inbound(inbound_id)


async def update_inbound(inbound_id: str, data: dict) -> dict:
    db = await get_db()
    fields = []
    values = []
    for key in ["protocol", "tag", "port", "listen", "rate_limit", "enabled"]:
        if key in data:
            fields.append(f"{key}=?")
            values.append(data[key])
    for key in ["settings", "stream"]:
        if key in data:
            fields.append(f"{key}=?")
            values.append(json.dumps(data[key]))
    if fields:
        values.append(inbound_id)
        await db.execute(f"UPDATE inbounds SET {', '.join(fields)} WHERE id=?", values)
        await db.commit()
    return await get_inbound(inbound_id)


async def delete_inbound(inbound_id: str):
    db = await get_db()
    await db.execute("DELETE FROM inbounds WHERE id = ?", (inbound_id,))
    await db.commit()


async def list_inbounds_for_node(node_id: str) -> list[dict]:
    """List all enabled inbounds for a node (used by agent sync)."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM inbounds WHERE node_id = ? AND enabled = 1 ORDER BY port", (node_id,))
    return [dict(r) for r in await cursor.fetchall()]


# ── Traffic ───────────────────────────────────────────────────────────────

async def get_traffic_summary():
    db = await get_db()
    cursor = await db.execute("SELECT * FROM traffic_summary")
    rows = await cursor.fetchall()
    summaries = {}
    for r in rows:
        summaries[r["node_id"]] = dict(r)
    return summaries


async def add_traffic(node_id: str, rx_bytes: int, tx_bytes: int):
    db = await get_db()
    await db.execute(
        """INSERT INTO traffic_summary (node_id, total_rx_bytes, total_tx_bytes,
           period_rx_bytes, period_tx_bytes, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(node_id) DO UPDATE SET
           total_rx_bytes = total_rx_bytes + ?,
           total_tx_bytes = total_tx_bytes + ?,
           period_rx_bytes = period_rx_bytes + ?,
           period_tx_bytes = period_tx_bytes + ?,
           updated_at = ?""",
        (node_id, rx_bytes, tx_bytes, rx_bytes, tx_bytes, time.time(),
         rx_bytes, tx_bytes, rx_bytes, tx_bytes, time.time())
    )
    now = time.time()
    await db.execute(
        "INSERT INTO traffic_log (node_id, rx_bytes, tx_bytes, period_start) VALUES (?, ?, ?, ?)",
        (node_id, rx_bytes, tx_bytes, now)
    )
    await db.commit()


async def reset_traffic(node_id: str):
    db = await get_db()
    now = time.time()
    await db.execute(
        "UPDATE traffic_log SET period_end = ? WHERE node_id = ? AND period_end IS NULL",
        (now, node_id))
    await db.execute(
        "UPDATE traffic_summary SET period_rx_bytes = 0, period_tx_bytes = 0, updated_at = ? WHERE node_id = ?",
        (now, node_id))
    await db.commit()


# ── Audit Log ─────────────────────────────────────────────────────────────

async def add_audit(action: str, target_type: str = None, target_id: str = None, detail: str = None):
    db = await get_db()
    await db.execute(
        "INSERT INTO audit_log (action, target_type, target_id, detail, created_at) VALUES (?, ?, ?, ?, ?)",
        (action, target_type, target_id, detail, time.time())
    )
    await db.commit()


async def list_audit(limit: int = 100):
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,))
    return [dict(r) for r in await cursor.fetchall()]


# ── Users ──────────────────────────────────────────────────────────────────

import hashlib
import secrets


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000)
    return h.hex(), salt


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    h, _ = hash_password(password, salt)
    return h == stored_hash


async def create_user(username: str, password: str, role: str = 'admin') -> dict:
    db = await get_db()
    pw_hash, salt = hash_password(password)
    await db.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, f"{salt}:{pw_hash}", role, time.time())
    )
    await db.commit()
    cursor = await db.execute(
        "SELECT id, username, display_name, avatar_url, role, created_at FROM users WHERE username = ?", (username,))
    return dict(await cursor.fetchone())


async def get_user_by_username(username: str) -> dict:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM users WHERE username = ?", (username,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def get_user_by_id(user_id: int) -> dict:
    db = await get_db()
    cursor = await db.execute(
        "SELECT id, username, display_name, avatar_url, role, created_at FROM users WHERE id = ?", (user_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def list_users() -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT id, username, display_name, avatar_url, role, created_at FROM users ORDER BY id")
    return [dict(r) for r in await cursor.fetchall()]


async def delete_user(user_id: int) -> bool:
    db = await get_db()
    cursor = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.commit()
    return cursor.rowcount > 0


async def update_user_role(user_id: int, role: str) -> bool:
    db = await get_db()
    cursor = await db.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (role, user_id))
    await db.commit()
    return cursor.rowcount > 0


async def change_password(user_id: int, new_password: str):
    db = await get_db()
    pw_hash, salt = hash_password(new_password)
    await db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (f"{salt}:{pw_hash}", user_id))
    await db.commit()


async def update_profile(user_id: int, username: str = None, display_name: str = None, avatar_url: str = None) -> dict:
    db = await get_db()
    if username is not None:
        await db.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
    if display_name is not None:
        await db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
    if avatar_url is not None:
        await db.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, user_id))
    await db.commit()
    return await get_user_by_id(user_id)


async def ensure_default_admin():
    db = await get_db()
    cursor = await db.execute("SELECT COUNT(*) as c FROM users")
    count = (await cursor.fetchone())['c']
    if count == 0:
        await create_user('admin', 'admin123', 'admin')
        return True
    return False


# ── Subscription Config ─────────────────────────────────────────────────────

async def list_sub_configs() -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT id, name, node_sources, rule_sources, include_local, output_format, "
        "filter_regex, access_token, replace_server_enabled, replace_server, sort_order, created_at, updated_at "
        "FROM sub_configs ORDER BY sort_order")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_sub_config(config_id: str) -> dict:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM sub_configs WHERE id = ?", (config_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def create_sub_config(data: dict) -> dict:
    db = await get_db()
    import uuid, secrets
    config_id = data.get("id") or f"sub-{uuid.uuid4().hex[:8]}"
    token = data.get("access_token") or secrets.token_urlsafe(24)
    now = time.time()
    await db.execute(
        "INSERT INTO sub_configs (id, name, node_sources, rule_sources, "
        "include_local, output_format, filter_regex, access_token, replace_server_enabled, replace_server, sort_order, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (config_id, data.get("name", ""), json.dumps(data.get("node_sources", [])),
         json.dumps(data.get("rule_sources", [])), data.get("include_local", 0),
         data.get("output_format", "clash"), data.get("filter_regex", ""),
         token, data.get("replace_server_enabled", 0), data.get("replace_server", ""),
         data.get("sort_order", 0), now, now))
    await db.commit()
    return await get_sub_config(config_id)


async def update_sub_config(config_id: str, data: dict) -> dict:
    db = await get_db()
    fields = []
    values = []
    for key in ["name", "include_local", "output_format", "filter_regex", "sort_order", "replace_server_enabled", "replace_server"]:
        if key in data:
            fields.append(f"{key}=?")
            values.append(data[key])
    for key in ["node_sources", "rule_sources"]:
        if key in data:
            fields.append(f"{key}=?")
            values.append(json.dumps(data[key]))
    if fields:
        fields.append("updated_at=?")
        values.append(time.time())
        values.append(config_id)
        await db.execute(f"UPDATE sub_configs SET {', '.join(fields)} WHERE id=?", values)
        await db.commit()
    return await get_sub_config(config_id)


async def delete_sub_config(config_id: str) -> bool:
    db = await get_db()
    cursor = await db.execute("DELETE FROM sub_configs WHERE id=?", (config_id,))
    await db.commit()
    return cursor.rowcount > 0


async def get_sub_by_token(token: str) -> dict:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM sub_configs WHERE access_token=?", (token,))
    row = await cursor.fetchone()
    return dict(row) if row else None


# ── Groups ─────────────────────────────────────────────────────────────────

async def list_groups() -> list[dict]:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM groups ORDER BY name")
    return [dict(r) for r in await cursor.fetchall()]


async def get_group(group_id: str) -> dict:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM groups WHERE id=?", (group_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def create_group(name: str, description: str = "") -> dict:
    db = await get_db()
    import uuid
    gid = f"grp-{uuid.uuid4().hex[:8]}"
    now = time.time()
    await db.execute(
        "INSERT INTO groups (id, name, description, created_at) VALUES (?,?,?,?)",
        (gid, name, description, now))
    await db.commit()
    return await get_group(gid)


async def update_group(group_id: str, name: str = None, description: str = None) -> dict:
    db = await get_db()
    if name is not None:
        await db.execute("UPDATE groups SET name=? WHERE id=?", (name, group_id))
    if description is not None:
        await db.execute("UPDATE groups SET description=? WHERE id=?", (description, group_id))
    await db.commit()
    return await get_group(group_id)


async def delete_group(group_id: str):
    db = await get_db()
    await db.execute("DELETE FROM groups WHERE id=?", (group_id,))
    await db.commit()


# ── Group-Node membership ──────────────────────────────────────────────────

async def get_group_nodes(group_id: str) -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT n.*, ns.cpu_percent, ns.mem_percent, ns.net_rx_speed, ns.net_tx_speed, "
        "ns.realm_status, ns.ss_status, ns.uptime_seconds "
        "FROM group_nodes gn JOIN nodes n ON gn.node_id=n.id "
        "LEFT JOIN ("
        "  SELECT node_id, cpu_percent, mem_percent, net_rx_speed, net_tx_speed, "
        "  realm_status, ss_status, uptime_seconds, "
        "  ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY id DESC) as rn "
        "  FROM node_stats"
        ") ns ON n.id=ns.node_id AND ns.rn=1 "
        "WHERE gn.group_id=? ORDER BY n.created_at", (group_id,))
    return [dict(r) for r in await cursor.fetchall()]


async def add_nodes_to_group(group_id: str, node_ids: list[str]):
    db = await get_db()
    for nid in node_ids:
        await db.execute("INSERT OR IGNORE INTO group_nodes (group_id, node_id) VALUES (?,?)", (group_id, nid))
    await db.commit()


async def remove_nodes_from_group(group_id: str, node_ids: list[str]):
    db = await get_db()
    for nid in node_ids:
        await db.execute("DELETE FROM group_nodes WHERE group_id=? AND node_id=?", (group_id, nid))
    await db.commit()


# ── Group-Inbound membership ───────────────────────────────────────────────

async def get_group_inbounds(group_id: str) -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT i.* FROM group_inbounds gi JOIN inbounds i ON gi.inbound_id=i.id "
        "WHERE gi.group_id=? ORDER BY i.port", (group_id,))
    return [dict(r) for r in await cursor.fetchall()]


async def add_inbounds_to_group(group_id: str, inbound_ids: list[str]):
    db = await get_db()
    for iid in inbound_ids:
        await db.execute("INSERT OR IGNORE INTO group_inbounds (group_id, inbound_id) VALUES (?,?)", (group_id, iid))
    await db.commit()


async def remove_inbounds_from_group(group_id: str, inbound_ids: list[str]):
    db = await get_db()
    for iid in inbound_ids:
        await db.execute("DELETE FROM group_inbounds WHERE group_id=? AND inbound_id=?", (group_id, iid))
    await db.commit()


# ── User-Group authorization ───────────────────────────────────────────────

async def get_user_groups(user_id: int) -> list[str]:
    """Get list of group IDs this user is authorized for. Auto-removes from groups where traffic quota exceeded."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT group_id FROM user_groups WHERE user_id=?", (user_id,))
    groups = [r["group_id"] for r in await cursor.fetchall()]

    # Enforce traffic quotas: remove user from groups where limit exceeded
    removed = False
    for gid in list(groups):
        over, used, limit = await check_user_group_quota(user_id, gid)
        if over:
            await db.execute(
                "DELETE FROM user_groups WHERE user_id=? AND group_id=?",
                (user_id, gid))
            groups.remove(gid)
            removed = True
    if removed:
        await db.commit()

    return groups


async def get_group_users(group_id: str) -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT u.id, u.username, u.display_name, u.role "
        "FROM user_groups ug JOIN users u ON ug.user_id=u.id "
        "WHERE ug.group_id=? ORDER BY u.username", (group_id,))
    return [dict(r) for r in await cursor.fetchall()]


async def set_group_users(group_id: str, user_ids: list[int]):
    """Replace all user assignments for a group with the given list."""
    db = await get_db()
    await db.execute("DELETE FROM user_groups WHERE group_id=?", (group_id,))
    for uid in user_ids:
        await db.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?,?)", (uid, group_id))
    await db.commit()


# ── Permission-filtered queries ────────────────────────────────────────────

async def list_nodes_for_user(user_id: int = None, user_role: str = None) -> list[dict]:
    """List nodes — admins see all, regular users see only authorized groups."""
    db = await get_db()
    if user_role == "admin":
        return await list_nodes()
    # Regular user: filter by authorized groups
    group_ids = await get_user_groups(user_id)
    if not group_ids:
        return []
    placeholders = ",".join(["?" for _ in group_ids])
    cursor = await db.execute(
        f"SELECT DISTINCT n.*, ns.cpu_percent, ns.mem_percent, ns.net_rx_speed, ns.net_tx_speed, "
        f"ns.realm_status, ns.ss_status, ns.uptime_seconds, ns.recorded_at as stats_at "
        f"FROM nodes n "
        f"JOIN group_nodes gn ON n.id=gn.node_id "
        f"LEFT JOIN ("
        f"  SELECT node_id, cpu_percent, mem_percent, net_rx_speed, net_tx_speed, "
        f"  realm_status, ss_status, uptime_seconds, recorded_at, "
        f"  ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY id DESC) as rn "
        f"  FROM node_stats"
        f") ns ON n.id=ns.node_id AND ns.rn=1 "
        f"WHERE gn.group_id IN ({placeholders}) "
        f"ORDER BY n.created_at DESC",
        group_ids)
    return [dict(r) for r in await cursor.fetchall()]


async def list_forwards_for_user(user_id: int = None, user_role: str = None, node_id: str = None) -> list[dict]:
    """List forwards — admins see all, regular users see only authorized groups' node forwards."""
    db = await get_db()
    if user_role == "admin":
        return await list_forwards(node_id)
    # Regular user: filter by authorized groups
    group_ids = await get_user_groups(user_id)
    if not group_ids:
        return []
    placeholders = ",".join(["?" for _ in group_ids])
    if node_id:
        cursor = await db.execute(
            f"SELECT DISTINCT f.* FROM forwards f "
            f"JOIN group_nodes gn ON f.node_id=gn.node_id "
            f"WHERE gn.group_id IN ({placeholders}) AND f.node_id=? "
            f"ORDER BY f.created_at DESC",
            [*group_ids, node_id])
    else:
        cursor = await db.execute(
            f"SELECT DISTINCT f.* FROM forwards f "
            f"JOIN group_nodes gn ON f.node_id=gn.node_id "
            f"WHERE gn.group_id IN ({placeholders}) "
            f"ORDER BY f.created_at DESC",
            group_ids)
    return [dict(r) for r in await cursor.fetchall()]


async def list_inbounds_for_user(user_id: int = None, user_role: str = None) -> list[dict]:
    """List inbounds — admins see all, regular users see only authorized groups."""
    db = await get_db()
    if user_role == "admin":
        return await list_inbounds()
    group_ids = await get_user_groups(user_id)
    if not group_ids:
        return []
    placeholders = ",".join(["?" for _ in group_ids])
    cursor = await db.execute(
        f"SELECT DISTINCT i.* FROM inbounds i "
        f"JOIN group_inbounds gi ON i.id=gi.inbound_id "
        f"WHERE gi.group_id IN ({placeholders}) "
        f"ORDER BY i.port",
        group_ids)
    return [dict(r) for r in await cursor.fetchall()]


# ── Batch operations ───────────────────────────────────────────────────────

async def batch_delete_nodes(node_ids: list[str]) -> int:
    db = await get_db()
    placeholders = ",".join(["?" for _ in node_ids])
    cursor = await db.execute(f"DELETE FROM nodes WHERE id IN ({placeholders})", node_ids)
    await db.commit()
    return cursor.rowcount


async def batch_delete_forwards(forward_ids: list[str]) -> int:
    db = await get_db()
    placeholders = ",".join(["?" for _ in forward_ids])
    cursor = await db.execute(f"DELETE FROM forwards WHERE id IN ({placeholders})", forward_ids)
    await db.commit()
    return cursor.rowcount


async def batch_delete_inbounds(inbound_ids: list[str]) -> int:
    db = await get_db()
    placeholders = ",".join(["?" for _ in inbound_ids])
    cursor = await db.execute(f"DELETE FROM inbounds WHERE id IN ({placeholders})", inbound_ids)
    await db.commit()
    return cursor.rowcount


async def batch_replace_forwards_entry(forward_ids: list[str], new_entry_node_id: str, new_listen_port: int = None) -> int:
    """Replace the entry node for tunnel forwards. Updates node_id and reconfigures listen_addr."""
    db = await get_db()
    entry_node = await get_node(new_entry_node_id)
    if not entry_node:
        return 0
    count = 0
    for fwd_id in forward_ids:
        cursor = await db.execute("SELECT * FROM forwards WHERE id=?", (fwd_id,))
        fwd = await cursor.fetchone()
        if not fwd:
            continue
        old_listen = fwd["listen_addr"]
        new_listen = old_listen
        if new_listen_port is not None:
            new_listen = f"0.0.0.0:{new_listen_port}"
        await db.execute(
            "UPDATE forwards SET node_id=?, listen_addr=? WHERE id=?",
            (new_entry_node_id, new_listen, fwd_id))
        count += 1
    await db.commit()
    return count


async def batch_replace_forwards_exit(forward_ids: list[str], new_exit_node_id: str) -> int:
    """Replace the exit node for tunnel forwards. Updates the remote_addr target."""
    db = await get_db()
    exit_node = await get_node(new_exit_node_id)
    if not exit_node:
        return 0
    count = 0
    for fwd_id in forward_ids:
        cursor = await db.execute("SELECT * FROM forwards WHERE id=?", (fwd_id,))
        fwd = await cursor.fetchone()
        if not fwd:
            continue
        old_remote = fwd["remote_addr"]
        # Keep port from old remote, use new node's host/entry_ip
        old_port = old_remote.rsplit(":", 1)[-1]
        new_host = exit_node.get("entry_ip") or exit_node["host"]
        new_remote = f"{new_host}:{old_port}"
        await db.execute(
            "UPDATE forwards SET remote_addr=? WHERE id=?",
            (new_remote, fwd_id))
        # Also update tunnel's exit_node_id in wg_tunnels
        await db.execute(
            "UPDATE wg_tunnels SET exit_node_id=? WHERE id IN "
            "(SELECT tunnel_id FROM forwards WHERE id=? AND forward_type='tunnel')",
            (new_exit_node_id, fwd_id))
        count += 1
    await db.commit()
    return count


# ══════════════════════════════════════════════════════════════════
# Group Node Limits
# ══════════════════════════════════════════════════════════════════

async def get_group_node_limits(group_id: str) -> dict[str, int]:
    """Return {node_id: rate_limit_kbps} for a group."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT node_id, rate_limit_kbps FROM group_node_limits WHERE group_id=?", (group_id,))
    rows = await cursor.fetchall()
    return {r["node_id"]: r["rate_limit_kbps"] for r in rows}


async def set_group_node_limit(group_id: str, node_id: str, rate_limit_kbps: int):
    """Set or update per-group node speed limit. 0 = unlimited."""
    db = await get_db()
    if rate_limit_kbps <= 0:
        await db.execute(
            "DELETE FROM group_node_limits WHERE group_id=? AND node_id=?",
            (group_id, node_id))
    else:
        await db.execute(
            "INSERT INTO group_node_limits (group_id, node_id, rate_limit_kbps) VALUES (?,?,?) "
            "ON CONFLICT(group_id, node_id) DO UPDATE SET rate_limit_kbps=excluded.rate_limit_kbps",
            (group_id, node_id, rate_limit_kbps))
    await db.commit()


# ══════════════════════════════════════════════════════════════════
# User Group Traffic Limits
# ══════════════════════════════════════════════════════════════════

async def get_user_group_traffic_limits(user_id: int) -> dict[str, int]:
    """Return {group_id: traffic_limit_bytes} for a user. 0 = unlimited."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT group_id, traffic_limit_bytes FROM user_group_traffic_limits WHERE user_id=?",
        (user_id,))
    rows = await cursor.fetchall()
    return {r["group_id"]: r["traffic_limit_bytes"] for r in rows}


async def set_user_group_traffic_limit(user_id: int, group_id: str, traffic_limit_bytes: int):
    """Set per-user per-group traffic limit. 0 = unlimited."""
    db = await get_db()
    if traffic_limit_bytes <= 0:
        await db.execute(
            "DELETE FROM user_group_traffic_limits WHERE user_id=? AND group_id=?",
            (user_id, group_id))
    else:
        await db.execute(
            "INSERT INTO user_group_traffic_limits (user_id, group_id, traffic_limit_bytes) VALUES (?,?,?) "
            "ON CONFLICT(user_id, group_id) DO UPDATE SET traffic_limit_bytes=excluded.traffic_limit_bytes",
            (user_id, group_id, traffic_limit_bytes))
    await db.commit()


async def check_user_group_quota(user_id: int, group_id: str) -> tuple[bool, int, int]:
    """Check if user has exceeded group traffic quota.
    Returns (over_quota, used_bytes, limit_bytes)."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT traffic_limit_bytes FROM user_group_traffic_limits WHERE user_id=? AND group_id=?",
        (user_id, group_id))
    row = await cursor.fetchone()
    limit_bytes = row["traffic_limit_bytes"] if row else 0
    if limit_bytes <= 0:
        return (False, 0, 0)

    cursor = await db.execute(
        "SELECT node_id FROM group_nodes WHERE group_id=?", (group_id,))
    node_ids = [r["node_id"] for r in await cursor.fetchall()]
    if not node_ids:
        return (False, 0, limit_bytes)

    placeholders = ",".join("?" * len(node_ids))
    cursor = await db.execute(
        f"SELECT COALESCE(SUM(rx_bytes+tx_bytes),0) as total FROM traffic_summary WHERE node_id IN ({placeholders})",
        node_ids)
    row = await cursor.fetchone()
    used = row["total"] if row else 0
    return (used >= limit_bytes, used, limit_bytes)
