"""SQLite database initialization and connection management."""

import os
import sqlite3
import aiosqlite

DB_PATH = os.environ.get("DB_PATH", "/data/realm_panel.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-8000;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'transit',
    host TEXT NOT NULL,
    entry_ip TEXT,
    port_start INTEGER,
    port_end INTEGER,
    ssh_port INTEGER DEFAULT 22,
    ssh_user TEXT DEFAULT 'root',
    ssh_password TEXT,
    agent_port INTEGER DEFAULT 9876,
    agent_deployed INTEGER DEFAULT 0,
    status TEXT DEFAULT 'offline',
    agent_version TEXT,
    os_info TEXT,
    wg_private_key TEXT DEFAULT '',
    wg_public_key TEXT DEFAULT '',
    last_seen REAL,
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS node_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    cpu_percent REAL,
    mem_percent REAL,
    disk_percent REAL,
    net_rx_bytes INTEGER,
    net_tx_bytes INTEGER,
    net_rx_speed REAL,
    net_tx_speed REAL,
    realm_status TEXT,
    ss_status TEXT,
    uptime_seconds INTEGER,
    recorded_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS forwards (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    listen_addr TEXT NOT NULL,
    remote_addr TEXT NOT NULL,
    tls_mode TEXT DEFAULT 'none',
    cert_path TEXT,
    key_path TEXT,
    ca_path TEXT,
    rate_limit INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    forward_type TEXT DEFAULT 'port',
    tunnel_id TEXT,
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS ss_nodes (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    method TEXT DEFAULT '2022-blake3-chacha20-poly1305',
    password TEXT NOT NULL,
    rate_limit INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at REAL DEFAULT (strftime('%s','now'))
);

-- New sing-box inbound table (replaces ss_nodes)
CREATE TABLE IF NOT EXISTS inbounds (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL DEFAULT 'shadowsocks',
    tag TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL,
    listen TEXT DEFAULT '0.0.0.0',
    settings TEXT NOT NULL DEFAULT '{}',
    stream TEXT NOT NULL DEFAULT '{}',
    rate_limit INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS traffic_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    forward_id TEXT,
    inbound_id TEXT,
    rx_bytes INTEGER DEFAULT 0,
    tx_bytes INTEGER DEFAULT 0,
    period_start REAL NOT NULL,
    period_end REAL,
    reset_at REAL
);

CREATE TABLE IF NOT EXISTS traffic_summary (
    node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    total_rx_bytes INTEGER DEFAULT 0,
    total_tx_bytes INTEGER DEFAULT 0,
    period_rx_bytes INTEGER DEFAULT 0,
    period_tx_bytes INTEGER DEFAULT 0,
    period_limit_rx INTEGER DEFAULT 0,
    period_limit_tx INTEGER DEFAULT 0,
    reset_day INTEGER DEFAULT 1,
    updated_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_node_stats_node ON node_stats(node_id, recorded_at);
CREATE INDEX IF NOT EXISTS idx_traffic_log_node ON traffic_log(node_id, period_start);
CREATE INDEX IF NOT EXISTS idx_forwards_node ON forwards(node_id);
CREATE INDEX IF NOT EXISTS idx_ss_nodes_node ON ss_nodes(node_id);
CREATE INDEX IF NOT EXISTS idx_inbounds_node ON inbounds(node_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS sub_configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    node_sources TEXT DEFAULT '[]',
    rule_sources TEXT DEFAULT '[]',
    include_local INTEGER DEFAULT 0,
    output_format TEXT DEFAULT 'clash',
    filter_regex TEXT DEFAULT '',
    access_token TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    replace_server_enabled INTEGER DEFAULT 0,
    replace_server TEXT DEFAULT '',
    created_at REAL DEFAULT (strftime('%s','now')),
    updated_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    avatar_url TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'admin',
    created_at REAL DEFAULT (strftime('%s','now'))
);

-- WireGuard tunnel metadata (IP range + key exchange per tunnel)
CREATE TABLE IF NOT EXISTS wg_tunnels (
    id TEXT PRIMARY KEY,
    entry_node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    exit_node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    tunnel_ip_cidr TEXT NOT NULL DEFAULT '10.99.0.0/30',
    entry_wg_ip TEXT NOT NULL,
    exit_wg_ip TEXT NOT NULL,
    listen_port INTEGER NOT NULL DEFAULT 51820,
    created_at REAL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_wg_tunnels_entry ON wg_tunnels(entry_node_id);
CREATE INDEX IF NOT EXISTS idx_wg_tunnels_exit ON wg_tunnels(exit_node_id);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS group_nodes (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_group_nodes_node ON group_nodes(node_id);

CREATE TABLE IF NOT EXISTS group_inbounds (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    inbound_id TEXT NOT NULL REFERENCES inbounds(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, inbound_id)
);
CREATE INDEX IF NOT EXISTS idx_group_inbounds_inbound ON group_inbounds(inbound_id);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS group_node_limits (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rate_limit_kbps INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, node_id)
);

CREATE TABLE IF NOT EXISTS user_group_traffic_limits (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, group_id)
);
"""

# Shared connection pool: single connection with write serialization lock
import asyncio

_db_conn: aiosqlite.Connection | None = None
_db_lock = asyncio.Lock()


async def get_db() -> aiosqlite.Connection:
    """Get the shared async database connection (created once, reused)."""
    global _db_conn
    if _db_conn is None:
        _db_conn = await aiosqlite.connect(DB_PATH)
        _db_conn.row_factory = aiosqlite.Row
        await _db_conn.execute("PRAGMA journal_mode=WAL")
        await _db_conn.execute("PRAGMA foreign_keys=ON")
        await _db_conn.execute("PRAGMA synchronous=NORMAL")
        await _db_conn.execute("PRAGMA cache_size=-8000")
        await _db_conn.execute("PRAGMA busy_timeout=5000")
    return _db_conn


async def db_execute(sql: str, params: tuple = ()):
    """Execute a write query with automatic commit (serialized via lock)."""
    db = await get_db()
    async with _db_lock:
        cursor = await db.execute(sql, params)
        await db.commit()
        return cursor


async def db_fetch(sql: str, params: tuple = ()):
    """Execute a read query (no lock needed for WAL reads)."""
    db = await get_db()
    return await db.execute(sql, params)


async def init_db():
    """Initialize database schema (called at startup)."""
    db = await get_db()
    await db.executescript(SCHEMA)
    await db.commit()


def _migrate_ss_to_inbounds(db: sqlite3.Connection):
    """Migrate existing ss_nodes to inbounds table."""
    cursor = db.execute("SELECT COUNT(*) as c FROM inbounds")
    if cursor.fetchone()["c"] > 0:
        return  # already migrated
    rows = db.execute("SELECT * FROM ss_nodes").fetchall()
    import json, uuid
    count = 0
    for row in rows:
        inbound_id = f"in-{uuid.uuid4().hex[:8]}"
        tag = f"ss-{row['port']}"
        settings = json.dumps({
            "method": row["method"],
            "password": row["password"],
        })
        stream = json.dumps({"network": "tcp"})
        try:
            db.execute(
                "INSERT INTO inbounds (id, node_id, protocol, tag, port, listen, settings, stream, rate_limit, enabled, created_at) "
                "VALUES (?, ?, 'shadowsocks', ?, ?, '0.0.0.0', ?, ?, ?, ?, ?)",
                (inbound_id, row["node_id"], tag, row["port"], settings, stream, row["rate_limit"], row["enabled"], row["created_at"])
            )
            count += 1
        except Exception:
            pass
    if count:
        print(f"[migration] Migrated {count} ss_nodes → inbounds")
    db.commit()


def _migrate_default_group(db: sqlite3.Connection):
    """Create default group with all existing resources if groups table is empty."""
    cursor = db.execute("SELECT COUNT(*) as c FROM groups")
    if cursor.fetchone()["c"] > 0:
        return
    import time as _time
    db.execute(
        "INSERT INTO groups (id, name, description, created_at) VALUES (?, ?, ?, ?)",
        ("default", "全部節點", "預設分組，包含所有現有資源", _time.time()))
    # Assign all existing nodes
    node_rows = db.execute("SELECT id FROM nodes").fetchall()
    for r in node_rows:
        db.execute("INSERT OR IGNORE INTO group_nodes (group_id, node_id) VALUES ('default', ?)", (r["id"],))
    # Assign all existing inbounds
    inbound_rows = db.execute("SELECT id FROM inbounds").fetchall()
    for r in inbound_rows:
        db.execute("INSERT OR IGNORE INTO group_inbounds (group_id, inbound_id) VALUES ('default', ?)", (r["id"],))
    # Assign all admin users
    user_rows = db.execute("SELECT id FROM users WHERE role='admin'").fetchall()
    for r in user_rows:
        db.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, 'default')", (r["id"],))
    print(f"[migration] Default group created with {len(node_rows)} nodes, {len(inbound_rows)} inbounds, {len(user_rows)} users")


def init_db_sync():
    """Synchronous init for startup."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    # Migration: add columns that may not exist in older databases
    migrations = {
        'users': [('display_name', "TEXT DEFAULT ''"), ('avatar_url', "TEXT DEFAULT ''")],
        'forwards': [('forward_type', "TEXT DEFAULT 'port'"), ('tunnel_id', 'TEXT')],
        'sub_configs': [('replace_server_enabled', 'INTEGER DEFAULT 0'), ('replace_server', "TEXT DEFAULT ''")],
        'nodes': [('wg_private_key', "TEXT DEFAULT ''"), ('wg_public_key', "TEXT DEFAULT ''")],
    }
    for table, cols in migrations.items():
        for col, typ in cols:
            try:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
            except sqlite3.OperationalError:
                pass
    # Migrate ss_nodes → inbounds
    _migrate_ss_to_inbounds(db)
    # Migrate: create default group + assign all existing resources/users
    _migrate_default_group(db)
    db.commit()
    db.close()
