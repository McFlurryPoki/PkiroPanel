"""
Subscription converter routes — manage configs and serve subscription endpoints.

/api/sub/configs        → CRUD
/api/sub/{config_id}    → Serve subscription (public, token-authenticated)
/api/sub/preview        → Preview parsed nodes from a URL or text
"""
import json
import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from panel import models
from panel.sub_parser import (
    parse_subscription, generate_output, filter_nodes,
    replace_nodes_server, local_ss_to_node
)

router = APIRouter(prefix="/api/sub", tags=["subscription"])

TIMEOUT = 15  # seconds for fetching external sources

# ── UA → output format mapping ──────────────────────────────────────────────

UA_FORMAT_MAP = {
    "clash": "clash",
    "shadowrocket": "base64",
    "v2ray": "base64",
    "sing-box": "singbox",
    "singbox": "singbox",
    "stash": "clash",
    "surge": "clash",
    "quantumult": "clash",
    "loon": "clash",
    "surfboard": "clash",
    "mihomo": "clash",
    "v2box": "base64",
    "fair": "base64",
    "oneclick": "base64",
    "streisand": "base64",
    "foxray": "base64",
}


def detect_format_from_ua(user_agent: str) -> str | None:
    """Detect output format from User-Agent header. Returns None if no match."""
    if not user_agent:
        return None
    ua_lower = user_agent.lower()
    for keyword, fmt in UA_FORMAT_MAP.items():
        if keyword in ua_lower:
            return fmt
    return None


# ── Config CRUD ─────────────────────────────────────────────────────────────

@router.get("/configs")
async def list_configs():
    configs = await models.list_sub_configs()
    for c in configs:
        c["node_sources"] = json.loads(c.get("node_sources", "[]"))
        c["rule_sources"] = json.loads(c.get("rule_sources", "[]"))
    return configs


@router.post("/configs")
async def create_config(data: dict):
    cfg = await models.create_sub_config(data)
    cfg["node_sources"] = json.loads(cfg.get("node_sources", "[]"))
    cfg["rule_sources"] = json.loads(cfg.get("rule_sources", "[]"))
    return cfg


@router.put("/configs/{config_id}")
async def update_config(config_id: str, data: dict):
    cfg = await models.update_sub_config(config_id, data)
    if not cfg:
        raise HTTPException(404, "Config not found")
    cfg["node_sources"] = json.loads(cfg.get("node_sources", "[]"))
    cfg["rule_sources"] = json.loads(cfg.get("rule_sources", "[]"))
    return cfg


@router.delete("/configs/{config_id}")
async def delete_config(config_id: str):
    ok = await models.delete_sub_config(config_id)
    if not ok:
        raise HTTPException(404, "Config not found")
    return {"ok": True}


# ── Preview (parse external sources) ────────────────────────────────────────

@router.post("/preview")
async def preview(data: dict):
    """Preview nodes from external source URL or raw text."""
    url = data.get("url", "")
    text = data.get("text", "")
    nodes = []
    rules = {}

    if url:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(url, follow_redirects=True)
                text = resp.text
        except Exception as e:
            raise HTTPException(400, f"Failed to fetch URL: {e}")

    if text:
        nodes, rules = parse_subscription(text)

    return {"nodes": nodes[:50], "count": len(nodes), "rules": rules}


# ── Subscription delivery endpoint ──────────────────────────────────────────

async def _fetch_source(url: str) -> str:
    """Fetch a subscription/rule source, return raw text."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(url, follow_redirects=True)
        return resp.text


def _is_url(text: str) -> bool:
    """Check if a string is an HTTP(S) URL."""
    return text.startswith("http://") or text.startswith("https://")


async def _build_subscription(config: dict, ua_format: str = None) -> str:
    """Fetch all sources, merge nodes, apply rules, generate output."""
    all_nodes = []
    all_rules = {"rules": [], "route": {"final": "direct"}}

    # 1. Fetch / parse node sources (URL or raw config strings)
    node_sources = config.get("node_sources")
    if isinstance(node_sources, str):
        node_sources = json.loads(node_sources)
    for src in (node_sources or []):
        if isinstance(src, str):
            content = src
        else:
            content = src.get("url", "") or src.get("text", "")
        if not content:
            continue
        try:
            if _is_url(content):
                text = await _fetch_source(content)
            else:
                text = content
            nodes, _ = parse_subscription(text)
            all_nodes.extend(nodes)
        except Exception:
            pass  # skip broken sources

    # 2. Fetch rule sources (GitHub raw, etc.)
    rule_sources = config.get("rule_sources")
    if isinstance(rule_sources, str):
        rule_sources = json.loads(rule_sources)
    for src in (rule_sources or []):
        url = src.get("url", "") if isinstance(src, dict) else src
        if not url:
            continue
        try:
            text = await _fetch_source(url)
            _, rules = parse_subscription(text)
            if rules.get("rules"):
                all_rules["rules"].extend(rules["rules"])
            if rules.get("rule-providers"):
                all_rules.setdefault("rule-providers", {}).update(rules["rule-providers"])
            if rules.get("route"):
                all_rules["route"] = rules["route"]
        except Exception:
            pass

    # 3. Deduplicate by name
    seen = set()
    unique_nodes = []
    for n in all_nodes:
        name = n.get("name", "")
        if name not in seen:
            seen.add(name)
            unique_nodes.append(n)

    # 4. Filter
    filtered = filter_nodes(unique_nodes, config.get("filter_regex", ""))

    # 5. Replace server if enabled
    if config.get("replace_server_enabled") and config.get("replace_server"):
        filtered = replace_nodes_server(filtered, config["replace_server"])

    # 6. Determine output format (UA override takes priority)
    output_format = ua_format or config.get("output_format", "clash")

    # 7. Generate output
    return generate_output(filtered, output_format, all_rules)


@router.get("/{config_id}")
async def serve_subscription(config_id: str, token: str = Query(None), request: Request = None):
    """Serve subscription. Auth via ?token= or Authorization header.
    Auto-detects output format from User-Agent for client compatibility."""
    cfg = await models.get_sub_config(config_id)
    if not cfg:
        raise HTTPException(404, "Subscription not found")
    if token != cfg.get("access_token"):
        raise HTTPException(403, "Invalid token")

    # UA-based format detection
    ua = request.headers.get("user-agent", "") if request else ""
    ua_format = detect_format_from_ua(ua)

    output = await _build_subscription(cfg, ua_format)
    fmt = ua_format or cfg.get("output_format", "clash")

    content_types = {
        "clash": "text/yaml; charset=utf-8",
        "singbox": "application/json; charset=utf-8",
        "base64": "text/plain; charset=utf-8",
    }
    return Response(content=output, media_type=content_types.get(fmt, "text/plain"))
