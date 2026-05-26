"""
Subscription converter — parse/generate/merge proxy subscriptions.

Supported inputs: Clash YAML, Sing-box JSON, base64-encoded links (SS/VMess/VLESS/Trojan/Hysteria2/TUIC/AnyTLS/WireGuard/SOCKS5/HTTP).
Supported outputs: Clash Meta YAML, Sing-box JSON, base64 link list.
"""
import json
import base64
import re
import yaml
from copy import deepcopy
from urllib.parse import quote, urlparse


# ── Base64 link parsers ─────────────────────────────────────────────────────

def parse_ss_url(url: str) -> dict | None:
    """ss://BASE64(method:password)@host:port or ss://BASE64(method:password@host:port)"""
    # Strip ss:// prefix
    raw = url
    if raw.startswith("ss://"):
        raw = raw[5:]
    # Check for #fragment (name)
    name = ""
    if "#" in raw:
        raw, name = raw.split("#", 1)
        name = quote(name)  # URL decode
    try:
        decoded = base64.urlsafe_b64decode(raw + "==").decode()
    except Exception:
        return None
    # Format: method:password@host:port
    m = re.match(r"^(.+?):(.+?)@(.+?):(\d+)$", decoded)
    if not m:
        return None
    return {
        "type": "ss",
        "name": name or f"{m.group(3)}:{m.group(4)}",
        "server": m.group(3),
        "port": int(m.group(4)),
        "method": m.group(1),
        "password": m.group(2),
    }


def parse_vmess_url(url: str) -> dict | None:
    """vmess://BASE64(JSON)"""
    raw = url
    if raw.startswith("vmess://"):
        raw = raw[8:]
    try:
        decoded = base64.urlsafe_b64decode(raw + "==").decode()
        cfg = json.loads(decoded)
        return {
            "type": "vmess",
            "name": cfg.get("ps", f"{cfg.get('add','?')}:{cfg.get('port','?')}"),
            "server": cfg.get("add", ""),
            "port": int(cfg.get("port", 0)),
            "uuid": cfg.get("id", ""),
            "alter_id": cfg.get("aid", 0),
            "network": cfg.get("net", "tcp"),
            "tls": cfg.get("tls", "none"),
        }
    except Exception:
        return None


def parse_vless_url(url: str) -> dict | None:
    """vless://uuid@host:port?params#name"""
    raw = url
    if raw.startswith("vless://"):
        raw = raw[8:]
    name = ""
    if "#" in raw:
        raw, name = raw.split("#", 1)
    try:
        m = re.match(r"^(.+?)@(.+?):(\d+)(\?.*)?$", raw)
        if not m:
            return None
        uuid, host, port, qs = m.group(1), m.group(2), int(m.group(3)), m.group(4) or ""
        params = {}
        if qs:
            qs = qs.lstrip("?")
            for kv in qs.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = v
        return {
            "type": "vless",
            "name": name or f"{host}:{port}",
            "server": host,
            "port": port,
            "uuid": uuid,
            "flow": params.get("flow", ""),
            "network": params.get("type", "tcp"),
            "tls": params.get("security", "none"),
        }
    except Exception:
        return None


def parse_trojan_url(url: str) -> dict | None:
    """trojan://password@host:port?params#name"""
    raw = url
    if raw.startswith("trojan://"):
        raw = raw[9:]
    name = ""
    if "#" in raw:
        raw, name = raw.split("#", 1)
    try:
        m = re.match(r"^(.+?)@(.+?):(\d+)(\?.*)?$", raw)
        if not m:
            return None
        password, host, port, qs = m.group(1), m.group(2), int(m.group(3)), m.group(4) or ""
        return {
            "type": "trojan",
            "name": name or f"{host}:{port}",
            "server": host,
            "port": port,
            "password": password,
        }
    except Exception:
        return None


def _parse_query_params(qs: str) -> dict:
    """Parse query string params into a dict."""
    params = {}
    if qs:
        qs = qs.lstrip("?")
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = v
    return params


def _parse_user_pass_host_port(url: str, protocol: str) -> tuple:
    """Parse user:pass@host:port?params#name from URL, return (user, password, host, port, params, name)."""
    raw = url
    prefix = f"{protocol}://"
    if raw.startswith(prefix):
        raw = raw[len(prefix):]
    name = ""
    if "#" in raw:
        raw, name = raw.split("#", 1)
    params = {}
    if "?" in raw:
        raw, qs = raw.split("?", 1)
        params = _parse_query_params(qs)
    m = re.match(r"^(.+?):(.+?)@(.+?):(\d+)$", raw)
    if not m:
        # Try uuid:password or just password format
        m2 = re.match(r"^(.+?)@(.+?):(\d+)$", raw)
        if m2:
            return "", m2.group(1), m2.group(2), int(m2.group(3)), params, name
        return None, None, None, None, params, name
    return m.group(1), m.group(2), m.group(3), int(m.group(4)), params, name


def parse_hy2_url(url: str) -> dict | None:
    """hysteria2://password@host:port?params#name or hy2://password@host:port"""
    user, password, host, port, params, name = _parse_user_pass_host_port(url, "hysteria2")
    if not host:
        if url.startswith("hy2://"):
            user, password, host, port, params, name = _parse_user_pass_host_port(url, "hy2")
        if not host:
            return None
    return {
        "type": "hysteria2",
        "name": name or f"{host}:{port}",
        "server": host,
        "port": port,
        "password": password,
        "sni": params.get("sni", ""),
        "insecure": params.get("insecure", "0") == "1",
        "obfs": params.get("obfs", ""),
        "obfs_password": params.get("obfs-password", ""),
        "up_mbps": int(params.get("upmbps", 0)),
        "down_mbps": int(params.get("downmbps", 0)),
    }


def parse_hysteria_url(url: str) -> dict | None:
    """hysteria://host:port?protocol=udp&auth=password&peer=sni&insecure=1#name (v1 format)"""
    raw = url
    if raw.startswith("hysteria://"):
        raw = raw[9:]
    name = ""
    if "#" in raw:
        raw, name = raw.split("#", 1)
    params = {}
    if "?" in raw:
        raw, qs = raw.split("?", 1)
        params = _parse_query_params(qs)
    m = re.match(r"^(.+?):(\d+)$", raw)
    if not m:
        return None
    return {
        "type": "hysteria",
        "name": name or f"{m.group(1)}:{m.group(2)}",
        "server": m.group(1),
        "port": int(m.group(2)),
        "password": params.get("auth", params.get("auth_str", "")),
        "sni": params.get("peer", ""),
        "insecure": params.get("insecure", "0") == "1",
        "up_mbps": int(params.get("upmbps", 0)),
        "down_mbps": int(params.get("downmbps", 0)),
        "protocol": params.get("protocol", "udp"),
    }


def parse_tuic_url(url: str) -> dict | None:
    """tuic://uuid:password@host:port?params#name"""
    user, password, host, port, params, name = _parse_user_pass_host_port(url, "tuic")
    if not host:
        return None
    return {
        "type": "tuic",
        "name": name or f"{host}:{port}",
        "server": host,
        "port": port,
        "uuid": user,
        "password": password,
        "sni": params.get("sni", ""),
        "insecure": params.get("allow_insecure", params.get("insecure", "0")) == "1",
        "alpn": params.get("alpn", ""),
        "congestion": params.get("congestion_control", "bbr"),
        "udp_relay": params.get("udp_relay_mode", "native"),
    }


def parse_anytls_url(url: str) -> dict | None:
    """anytls://password@host:port?params#name"""
    user, password, host, port, params, name = _parse_user_pass_host_port(url, "anytls")
    if not host:
        return None
    return {
        "type": "anytls",
        "name": name or f"{host}:{port}",
        "server": host,
        "port": port,
        "password": password,
        "sni": params.get("sni", ""),
        "alpn": params.get("alpn", ""),
        "utls": params.get("utls", ""),
        "insecure": params.get("insecure", "0") == "1",
    }


def parse_wg_url(url: str) -> dict | None:
    """wireguard://privateKey@endpoint:port?publicKey=xxx&address=10.0.0.2/24&mtu=1420#name"""
    user, password, host, port, params, name = _parse_user_pass_host_port(url, "wireguard")
    if not host:
        return None
    # privateKey is in 'user' field
    private_key = user or password
    return {
        "type": "wireguard",
        "name": name or f"wg-{host}:{port}",
        "server": host,
        "port": port,
        "private_key": private_key,
        "public_key": params.get("publicKey", params.get("publickey", "")),
        "address": params.get("address", ""),
        "mtu": int(params.get("mtu", 1420)),
        "dns": params.get("dns", ""),
        "allowed_ips": params.get("allowedips", "0.0.0.0/0"),
    }


def parse_socks_url(url: str) -> dict | None:
    """socks5://host:port?username=xxx&password=xxx#name"""
    raw = url
    if raw.startswith("socks5://"):
        raw = raw[9:]
    name = ""
    if "#" in raw:
        raw, name = raw.split("#", 1)
    params = {}
    if "?" in raw:
        raw, qs = raw.split("?", 1)
        params = _parse_query_params(qs)
    m = re.match(r"^(.+?):(\d+)$", raw)
    if not m:
        return None
    return {
        "type": "socks5",
        "name": name or f"socks-{m.group(1)}:{m.group(2)}",
        "server": m.group(1),
        "port": int(m.group(2)),
        "username": params.get("username", ""),
        "password": params.get("password", ""),
    }


def parse_http_url(url: str) -> dict | None:
    """http://host:port?username=xxx&password=xxx#name or https:// (as HTTP proxy)"""
    raw = url
    if raw.startswith("https://"):
        raw = raw[8:]
    elif raw.startswith("http://"):
        raw = raw[7:]
    name = ""
    if "#" in raw:
        raw, name = raw.split("#", 1)
    params = {}
    if "?" in raw:
        raw, qs = raw.split("?", 1)
        params = _parse_query_params(qs)
    m = re.match(r"^(.+?):(\d+)$", raw)
    if not m:
        return None
    return {
        "type": "http",
        "name": name or f"http-{m.group(1)}:{m.group(2)}",
        "server": m.group(1),
        "port": int(m.group(2)),
        "username": params.get("username", ""),
        "password": params.get("password", ""),
        "tls": url.startswith("https://"),
    }


LINK_PARSERS = [
    ("ss://", parse_ss_url),
    ("vmess://", parse_vmess_url),
    ("vless://", parse_vless_url),
    ("trojan://", parse_trojan_url),
    ("hysteria2://", parse_hy2_url),
    ("hy2://", parse_hy2_url),
    ("hysteria://", parse_hysteria_url),
    ("tuic://", parse_tuic_url),
    ("anytls://", parse_anytls_url),
    ("wireguard://", parse_wg_url),
    ("socks5://", parse_socks_url),
    ("http://", parse_http_url),
    ("https://", parse_http_url),
]


def parse_link_list(text: str) -> list[dict]:
    """Parse a newline-separated list of proxy URLs."""
    nodes = []
    for line in text.strip().split("\n"):
        line = line.strip()
        for prefix, parser in LINK_PARSERS:
            if line.startswith(prefix):
                node = parser(line)
                if node:
                    nodes.append(node)
                break
    return nodes


# ── Clash YAML parser ───────────────────────────────────────────────────────

def parse_clash_yaml(text: str) -> tuple[list[dict], dict]:
    """Parse Clash YAML, return (proxies, rules)."""
    try:
        cfg = yaml.safe_load(text)
    except Exception:
        return [], {}
    proxies = []
    for p in cfg.get("proxies", []):
        ptype = p.get("type", "ss")
        node = {"name": p.get("name", ""), "type": ptype}
        if ptype == "ss":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        method=p.get("cipher", "aes-256-gcm"), password=p.get("password", ""))
        elif ptype == "vmess":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        uuid=p.get("uuid", ""), alter_id=p.get("alterId", 0),
                        network=p.get("network", "tcp"), tls=p.get("tls", False))
        elif ptype == "vless":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        uuid=p.get("uuid", ""), flow=p.get("flow", ""))
        elif ptype == "trojan":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        password=p.get("password", ""))
        elif ptype == "hysteria2":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        password=p.get("password", ""), sni=p.get("sni", ""),
                        obfs=p.get("obfs", ""), obfs_password=p.get("obfs-password", ""),
                        up_mbps=p.get("up", 0), down_mbps=p.get("down", 0))
        elif ptype == "hysteria":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        password=p.get("auth_str", p.get("auth", "")),
                        sni=p.get("sni", ""),
                        up_mbps=p.get("up", 0), down_mbps=p.get("down", 0))
        elif ptype == "tuic":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        uuid=p.get("uuid", ""), password=p.get("password", ""),
                        sni=p.get("sni", ""), alpn=p.get("alpn", ""),
                        congestion=p.get("congestion-controller", "bbr"))
        elif ptype == "wireguard":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        private_key=p.get("private-key", ""), public_key=p.get("public-key", ""),
                        address=p.get("ip", ""), mtu=p.get("mtu", 1420))
        elif ptype == "socks5":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        username=p.get("username", ""), password=p.get("password", ""))
        elif ptype == "http":
            node.update(server=p.get("server", ""), port=p.get("port", 0),
                        username=p.get("username", ""), password=p.get("password", ""),
                        tls=p.get("tls", False))
        proxies.append(node)
    rules = {"rules": cfg.get("rules", []), "rule-providers": cfg.get("rule-providers", {})}
    return proxies, rules


# ── Sing-box JSON parser ────────────────────────────────────────────────────

def parse_singbox_json(text: str) -> tuple[list[dict], dict]:
    """Parse Sing-box JSON, return (outbounds, rules)."""
    try:
        cfg = json.loads(text)
    except Exception:
        return [], {}
    proxies = []
    for o in cfg.get("outbounds", []):
        if o.get("tag") in ("direct", "block", "dns-out"):
            continue
        otype = o.get("type", "ss")
        node = {"name": o.get("tag", ""), "type": otype}
        if otype == "shadowsocks":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        method=o.get("method", ""), password=o.get("password", ""))
            node["type"] = "ss"
        elif otype == "vmess":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        uuid=o.get("uuid", ""), alter_id=o.get("alter_id", 0))
        elif otype == "vless":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        uuid=o.get("uuid", ""), flow=o.get("flow", ""))
        elif otype == "trojan":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        password=o.get("password", ""))
        elif otype == "hysteria2":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        password=o.get("password", ""),
                        sni=o.get("tls", {}).get("server_name", ""),
                        obfs=o.get("obfs", {}).get("type", ""),
                        up_mbps=o.get("up_mbps", 0), down_mbps=o.get("down_mbps", 0))
        elif otype == "hysteria":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        password=o.get("auth_str", ""),
                        up_mbps=o.get("up_mbps", 0), down_mbps=o.get("down_mbps", 0))
        elif otype == "tuic":
            tls = o.get("tls", {})
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        uuid=o.get("uuid", ""), password=o.get("password", ""),
                        sni=tls.get("server_name", ""), alpn="/".join(tls.get("alpn", []) or []),
                        congestion=o.get("congestion_control", "bbr"))
        elif otype == "wireguard":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        private_key=o.get("private_key", ""),
                        public_key=o.get("peer_public_key", ""),
                        address=o.get("local_address", [""])[0] if o.get("local_address") else "",
                        mtu=o.get("mtu", 1420))
        elif otype == "socks":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        username=o.get("username", ""), password=o.get("password", ""))
            node["type"] = "socks5"
        elif otype == "http":
            node.update(server=o.get("server", ""), port=o.get("server_port", 0),
                        username=o.get("username", ""), password=o.get("password", ""),
                        tls=bool(o.get("tls")))
        proxies.append(node)
    rules = {"route": cfg.get("route", {})}
    return proxies, rules


# ── Unified parser (detect format automatically) ─────────────────────────────

def parse_subscription(text: str) -> tuple[list[dict], dict]:
    """Auto-detect format, return (nodes, rules)."""
    text = text.strip()
    if not text:
        return [], {}
    # Try Clash YAML
    if text.startswith("proxies:") or text.startswith("Proxy") or "proxies:" in text[:200]:
        return parse_clash_yaml(text)
    # Try Sing-box JSON
    if text.startswith("{"):
        return parse_singbox_json(text)
    # Try base64 (common subscription encoding)
    try:
        decoded = base64.urlsafe_b64decode(text + "==").decode()
        if any(decoded.startswith(p) for p, _ in LINK_PARSERS):
            return parse_link_list(decoded), {}
    except Exception:
        pass
    # Plain link list
    return parse_link_list(text), {}


# ── Output generators ───────────────────────────────────────────────────────

CLASH_TEMPLATE = """mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
{proxies}

proxy-groups:
  - name: "🚀 自動選擇"
    type: url-test
    proxies:
{group_proxies}
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
{rules}
"""

SINGBOX_TEMPLATE = """{{
  "log": {{"level": "info"}},
  "inbounds": [{{
    "type": "mixed",
    "tag": "mixed-in",
    "listen": "127.0.0.1",
    "listen_port": 2080
  }}],
  "outbounds": [
{outbounds}
  ],
  "route": {route}
}}
"""


def _node_to_clash(node: dict) -> str:
    """Convert a node dict to Clash YAML proxy entry."""
    node_type = node.get("type", "ss")
    name = node.get("name", "unknown")
    server = node.get("server", "")
    port = node.get("port", 0)
    indent = "  "

    lines = [f"{indent}- name: \"{name}\""]
    if node_type == "ss":
        lines.append(f"{indent}  type: ss")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  cipher: {node.get('method', 'aes-256-gcm')}")
        lines.append(f"{indent}  password: \"{node.get('password', '')}\"")
    elif node_type == "vmess":
        lines.append(f"{indent}  type: vmess")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  uuid: {node.get('uuid', '')}")
        lines.append(f"{indent}  alterId: {node.get('alter_id', 0)}")
        lines.append(f"{indent}  cipher: auto")
        if node.get("tls"):
            lines.append(f"{indent}  tls: true")
        if node.get("network"):
            lines.append(f"{indent}  network: {node['network']}")
    elif node_type == "vless":
        lines.append(f"{indent}  type: vless")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  uuid: {node.get('uuid', '')}")
        if node.get("flow"):
            lines.append(f"{indent}  flow: {node['flow']}")
        if node.get("network"):
            lines.append(f"{indent}  network: {node['network']}")
    elif node_type == "trojan":
        lines.append(f"{indent}  type: trojan")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  password: \"{node.get('password', '')}\"")
    elif node_type == "hysteria2":
        lines.append(f"{indent}  type: hysteria2")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  password: \"{node.get('password', '')}\"")
        if node.get("sni"):
            lines.append(f"{indent}  sni: \"{node['sni']}\"")
        if node.get("obfs"):
            lines.append(f"{indent}  obfs: {node['obfs']}")
            if node.get("obfs_password"):
                lines.append(f"{indent}  obfs-password: \"{node['obfs_password']}\"")
        if node.get("up_mbps"):
            lines.append(f"{indent}  up: {node['up_mbps']}")
        if node.get("down_mbps"):
            lines.append(f"{indent}  down: {node['down_mbps']}")
    elif node_type == "hysteria":
        lines.append(f"{indent}  type: hysteria")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  auth_str: \"{node.get('password', '')}\"")
        if node.get("sni"):
            lines.append(f"{indent}  sni: \"{node['sni']}\"")
        if node.get("up_mbps"):
            lines.append(f"{indent}  up: {node['up_mbps']}")
        if node.get("down_mbps"):
            lines.append(f"{indent}  down: {node['down_mbps']}")
    elif node_type == "tuic":
        lines.append(f"{indent}  type: tuic")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  uuid: {node.get('uuid', '')}")
        lines.append(f"{indent}  password: \"{node.get('password', '')}\"")
        if node.get("sni"):
            lines.append(f"{indent}  sni: \"{node['sni']}\"")
        if node.get("alpn"):
            lines.append(f"{indent}  alpn: [{', '.join(repr(a) for a in node['alpn'].split('/') if a)}]")
        lines.append(f"{indent}  congestion-controller: {node.get('congestion', 'bbr')}")
    elif node_type == "wireguard":
        lines.append(f"{indent}  type: wireguard")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        lines.append(f"{indent}  private-key: \"{node.get('private_key', '')}\"")
        lines.append(f"{indent}  public-key: \"{node.get('public_key', '')}\"")
        if node.get("address"):
            lines.append(f"{indent}  ip: \"{node['address']}\"")
        if node.get("mtu"):
            lines.append(f"{indent}  mtu: {node['mtu']}")
    elif node_type == "socks5":
        lines.append(f"{indent}  type: socks5")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        if node.get("username"):
            lines.append(f"{indent}  username: \"{node['username']}\"")
        if node.get("password"):
            lines.append(f"{indent}  password: \"{node['password']}\"")
    elif node_type == "http":
        lines.append(f"{indent}  type: http")
        lines.append(f"{indent}  server: {server}")
        lines.append(f"{indent}  port: {port}")
        if node.get("username"):
            lines.append(f"{indent}  username: \"{node['username']}\"")
        if node.get("password"):
            lines.append(f"{indent}  password: \"{node['password']}\"")
        if node.get("tls"):
            lines.append(f"{indent}  tls: true")
    return "\n".join(lines)


def _node_to_singbox(node: dict) -> str:
    """Convert a node dict to Sing-box JSON outbound entry."""
    node_type = node.get("type", "ss")
    name = node.get("name", "unknown")
    server = node.get("server", "")
    port = node.get("port", 0)

    if node_type == "ss":
        entry = {
            "type": "shadowsocks",
            "tag": name,
            "server": server,
            "server_port": port,
            "method": node.get("method", "aes-256-gcm"),
            "password": node.get("password", ""),
        }
    elif node_type == "vmess":
        entry = {
            "type": "vmess",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": node.get("uuid", ""),
            "alter_id": node.get("alter_id", 0),
        }
    elif node_type == "vless":
        entry = {
            "type": "vless",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": node.get("uuid", ""),
            "flow": node.get("flow", ""),
        }
    elif node_type == "trojan":
        entry = {
            "type": "trojan",
            "tag": name,
            "server": server,
            "server_port": port,
            "password": node.get("password", ""),
        }
    elif node_type == "hysteria2":
        entry = {
            "type": "hysteria2",
            "tag": name,
            "server": server,
            "server_port": port,
            "password": node.get("password", ""),
        }
        if node.get("sni"):
            entry.setdefault("tls", {})
            entry["tls"]["enabled"] = True
            entry["tls"]["server_name"] = node["sni"]
            if node.get("insecure"):
                entry["tls"]["insecure"] = True
        if node.get("obfs"):
            entry["obfs"] = {"type": node["obfs"], "password": node.get("obfs_password", "")}
        if node.get("up_mbps"):
            entry["up_mbps"] = node["up_mbps"]
        if node.get("down_mbps"):
            entry["down_mbps"] = node["down_mbps"]
    elif node_type == "hysteria":
        entry = {
            "type": "hysteria",
            "tag": name,
            "server": server,
            "server_port": port,
            "auth_str": node.get("password", ""),
        }
        if node.get("up_mbps"):
            entry["up_mbps"] = node["up_mbps"]
        if node.get("down_mbps"):
            entry["down_mbps"] = node["down_mbps"]
    elif node_type == "tuic":
        entry = {
            "type": "tuic",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": node.get("uuid", ""),
            "password": node.get("password", ""),
            "congestion_control": node.get("congestion", "bbr"),
        }
        if node.get("sni") or node.get("alpn"):
            entry.setdefault("tls", {})
            entry["tls"]["enabled"] = True
            if node.get("sni"):
                entry["tls"]["server_name"] = node["sni"]
            if node.get("alpn"):
                entry["tls"]["alpn"] = [a for a in node["alpn"].split("/") if a]
            if node.get("insecure"):
                entry["tls"]["insecure"] = True
    elif node_type == "wireguard":
        entry = {
            "type": "wireguard",
            "tag": name,
            "server": server,
            "server_port": port,
            "private_key": node.get("private_key", ""),
            "peer_public_key": node.get("public_key", ""),
            "mtu": node.get("mtu", 1420),
        }
        if node.get("address"):
            entry["local_address"] = [node["address"]]
    elif node_type == "socks5":
        entry = {
            "type": "socks",
            "tag": name,
            "server": server,
            "server_port": port,
        }
        if node.get("username"):
            entry["username"] = node["username"]
        if node.get("password"):
            entry["password"] = node["password"]
    elif node_type == "http":
        entry = {
            "type": "http",
            "tag": name,
            "server": server,
            "server_port": port,
        }
        if node.get("username"):
            entry["username"] = node["username"]
        if node.get("password"):
            entry["password"] = node["password"]
        if node.get("tls"):
            entry["tls"] = {"enabled": True}
    else:
        return ""
    return "    " + json.dumps(entry, ensure_ascii=False)


def _node_to_link(node: dict) -> str:
    """Convert a node dict to a share link."""
    node_type = node.get("type", "ss")
    name = node.get("name", "")
    server = node.get("server", "")
    port = node.get("port", 0)

    if node_type == "ss":
        payload = base64.urlsafe_b64encode(
            f"{node.get('method','aes-256-gcm')}:{node.get('password','')}@{server}:{port}".encode()
        ).decode().rstrip("=")
        link = f"ss://{payload}"
        if name:
            link += f"#{name}"
        return link
    elif node_type == "vmess":
        cfg = json.dumps({
            "v": "2", "ps": name, "add": server, "port": port,
            "id": node.get("uuid", ""), "aid": node.get("alter_id", 0),
            "net": node.get("network", "tcp"), "type": "none",
            "tls": "tls" if node.get("tls") else ""
        })
        return f"vmess://{base64.urlsafe_b64encode(cfg.encode()).decode().rstrip('=')}"
    elif node_type == "vless":
        link = f"vless://{node.get('uuid','')}@{server}:{port}?"
        params = []
        if node.get("flow"):
            params.append(f"flow={node['flow']}")
        if node.get("network"):
            params.append(f"type={node['network']}")
        if node.get("tls"):
            params.append(f"security={node['tls']}")
        link += "&".join(params)
        if name:
            link += f"#{name}"
        return link
    elif node_type == "trojan":
        link = f"trojan://{node.get('password','')}@{server}:{port}"
        if node.get("sni"):
            link += f"?sni={node['sni']}"
        if name:
            link += f"#{name}"
        return link
    elif node_type == "hysteria2":
        params = []
        if node.get("sni"):
            params.append(f"sni={node['sni']}")
        if node.get("insecure"):
            params.append("insecure=1")
        if node.get("obfs"):
            params.append(f"obfs={node['obfs']}")
            if node.get("obfs_password"):
                params.append(f"obfs-password={node['obfs_password']}")
        link = f"hysteria2://{node.get('password','')}@{server}:{port}"
        if params:
            link += "?" + "&".join(params)
        if name:
            link += f"#{name}"
        return link
    elif node_type == "hysteria":
        params = [f"auth={node.get('password','')}"]
        if node.get("sni"):
            params.append(f"peer={node['sni']}")
        if node.get("insecure"):
            params.append("insecure=1")
        link = f"hysteria://{server}:{port}?" + "&".join(params)
        if name:
            link += f"#{name}"
        return link
    elif node_type == "tuic":
        params = []
        if node.get("sni"):
            params.append(f"sni={node['sni']}")
        if node.get("alpn"):
            params.append(f"alpn={node['alpn']}")
        if node.get("insecure"):
            params.append("allow_insecure=1")
        if node.get("congestion"):
            params.append(f"congestion_control={node['congestion']}")
        link = f"tuic://{node.get('uuid','')}:{node.get('password','')}@{server}:{port}"
        if params:
            link += "?" + "&".join(params)
        if name:
            link += f"#{name}"
        return link
    elif node_type == "wireguard":
        params = []
        if node.get("public_key"):
            params.append(f"publicKey={node['public_key']}")
        if node.get("address"):
            params.append(f"address={node['address']}")
        if node.get("mtu"):
            params.append(f"mtu={node['mtu']}")
        link = f"wireguard://{node.get('private_key','')}@{server}:{port}"
        if params:
            link += "?" + "&".join(params)
        if name:
            link += f"#{name}"
        return link
    elif node_type == "socks5":
        link = f"socks5://{server}:{port}"
        if name:
            link += f"#{name}"
        return link
    elif node_type == "http":
        scheme = "https" if node.get("tls") else "http"
        link = f"{scheme}://{server}:{port}"
        if name:
            link += f"#{name}"
        return link
    return ""


def local_ss_to_node(ss: dict, node_name: str) -> dict:
    """Convert a panel SS node to a standard node dict."""
    return {
        "type": "ss",
        "name": f"{node_name}-{ss['port']}",
        "server": "",  # filled by agent
        "port": ss.get("port", 0),
        "method": ss.get("method", "2022-blake3-chacha20-poly1305"),
        "password": ss.get("password", ""),
    }


def replace_nodes_server(nodes: list[dict], new_server: str) -> list[dict]:
    """Replace the server field of all nodes with a new IP/domain."""
    if not new_server:
        return nodes
    return [{**n, "server": new_server} for n in nodes]


def filter_nodes(nodes: list[dict], regex: str) -> list[dict]:
    """Filter nodes by name regex."""
    if not regex:
        return nodes
    try:
        pattern = re.compile(regex)
        return [n for n in nodes if pattern.search(n.get("name", ""))]
    except re.error:
        return nodes


def get_default_rules(output_format: str) -> dict:
    """Return sensible default rules when no third-party rules configured."""
    if output_format == "clash":
        return {
            "rules": [
                "DOMAIN-SUFFIX,local,DIRECT",
                "IP-CIDR,10.0.0.0/8,DIRECT",
                "IP-CIDR,127.0.0.0/8,DIRECT",
                "IP-CIDR,172.16.0.0/12,DIRECT",
                "IP-CIDR,192.168.0.0/16,DIRECT",
                "IP-CIDR,100.64.0.0/10,DIRECT",
                "DOMAIN-SUFFIX,cn,DIRECT",
                "DOMAIN-KEYWORD,baidu,DIRECT",
                "DOMAIN-KEYWORD,taobao,DIRECT",
                "DOMAIN-KEYWORD,alipay,DIRECT",
                "DOMAIN-KEYWORD,weixin,DIRECT",
                "DOMAIN-KEYWORD,qq.com,DIRECT",
                "DOMAIN-KEYWORD,bilibili,DIRECT",
                "DOMAIN-KEYWORD,zhihu,DIRECT",
                "DOMAIN-KEYWORD,jd.com,DIRECT",
                "DOMAIN-KEYWORD,meituan,DIRECT",
                "DOMAIN-KEYWORD,douyin,DIRECT",
                "GEOIP,CN,DIRECT",
                "MATCH,🚀 自動選擇",
            ]
        }
    elif output_format == "singbox":
        return {
            "route": {
                "rules": [
                    {"domain_suffix": ["cn"], "outbound": "direct"},
                    {"domain_keyword": ["baidu", "taobao", "alipay", "weixin", "qq.com", "bilibili", "zhihu", "jd.com", "meituan", "douyin"], "outbound": "direct"},
                    {"geoip": ["cn"], "outbound": "direct"},
                    {"ip_cidr": ["10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"], "outbound": "direct"},
                ],
                "final": "🚀 自動選擇"
            }
        }
    return {}


def generate_output(nodes: list[dict], output_format: str, rules: dict = None) -> str:
    """Generate subscription output in the requested format."""
    if not rules:
        rules = {}

    if output_format == "clash":
        proxies_text = "\n".join(_node_to_clash(n) for n in nodes)
        group_proxies = "\n".join(f"      - \"{n['name']}\"" for n in nodes)
        rules_text = ""
        effective_rules = rules if (rules and rules.get("rules")) else get_default_rules("clash")
        if effective_rules.get("rules"):
            rules_text = "\n".join(f"  - {r}" for r in effective_rules["rules"])
        else:
            rules_text = "  - MATCH,DIRECT"
        return CLASH_TEMPLATE.format(
            proxies=proxies_text,
            group_proxies=group_proxies or "      - DIRECT",
            rules=rules_text,
        )

    elif output_format == "singbox":
        direct_outbound = '    {"type": "direct", "tag": "direct"}'
        outbounds = ",\n".join(
            [_node_to_singbox(n) for n in nodes if _node_to_singbox(n)] + [direct_outbound]
        )
        effective_rules = rules if (rules and rules.get("route")) else get_default_rules("singbox")
        route = json.dumps(effective_rules.get("route", {"final": "direct"}), indent=2, ensure_ascii=False)
        return SINGBOX_TEMPLATE.format(outbounds=outbounds, route=route)

    elif output_format == "base64":
        links = "\n".join(_node_to_link(n) for n in nodes)
        return base64.urlsafe_b64encode(links.encode()).decode().rstrip("=")

    return ""
