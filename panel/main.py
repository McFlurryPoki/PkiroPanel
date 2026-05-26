"""TransetPanel — Main FastAPI application."""

import asyncio
import os
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from panel.database import init_db_sync
from panel.ws_handler import manager
from panel.routes import nodes, forwards, ss_nodes, traffic, audit, auth, sub, inbounds, groups


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db_sync()
    from panel.models import ensure_default_admin
    await ensure_default_admin()
    from panel.scheduler import scheduler_loop
    scheduler_task = asyncio.create_task(scheduler_loop())
    print(f"TransetPanel started on port {os.environ.get('PANEL_PORT', 32100)}")
    yield
    # Shutdown
    scheduler_task.cancel()
    print("TransetPanel shutting down")


app = FastAPI(title="TransetPanel", version="1.0.0", lifespan=lifespan)

# ── REST API routes ───────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(auth.users_router)
app.include_router(nodes.router)
app.include_router(forwards.router)
app.include_router(ss_nodes.router)
app.include_router(traffic.router)
app.include_router(audit.router)
app.include_router(sub.router)
app.include_router(inbounds.router)
app.include_router(groups.router)


# ── Agent WebSocket ───────────────────────────────────────────────────────
@app.websocket("/ws")
async def agent_ws(ws: WebSocket):
    node_id = await manager.connect(ws)
    if node_id:
        await manager.handle_agent(ws, node_id)


# ── Agent download endpoints (called by install script) ──────────────────
@app.get("/agent/config")
async def agent_config(node: str, token: str, request: Request = None):
    """Agent requests its config during install.
    Derives WebSocket URL from the actual request, not PANEL_URL env var."""
    import json
    from panel import models as m
    nd = await m.get_node(node)
    if not nd:
        return JSONResponse({"error": "node not found"}, 404)

    # Use request's base URL so install always gets the correct ws endpoint
    from urllib.parse import urlparse
    if request:
        # Prefer X-Forwarded-Proto/Forwarded headers (behind reverse proxy)
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
        scheme = forwarded_proto if forwarded_proto in ("http", "https") else request.url.scheme
        host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "localhost")
        host = host.split(":")[0]  # strip port from Host header
        port = request.url.port or (443 if scheme == "https" else 80)
        ws_scheme = "wss" if scheme == "https" else "ws"
        # Include port for non-standard ports (e.g., direct access on :32100)
        if port and port not in (80, 443):
            panel_ws = f"{ws_scheme}://{host}:{port}/ws"
        else:
            panel_ws = f"{ws_scheme}://{host}/ws"
    else:
        panel_url = os.environ.get("PANEL_URL", "http://localhost:32100")
        pu = urlparse(panel_url)
        ws_host = pu.hostname or "localhost"
        ws_port = pu.port or 32100
        ws_scheme = "wss" if pu.scheme == "https" else "ws"
        panel_ws = f"{ws_scheme}://{ws_host}:{ws_port}/ws"

    cfg = {
        "node_id": node,
        "panel_ws": panel_ws,
        "auth_token": os.environ.get("SECRET_KEY", "default")[:32],
        "agent_port": nd.get("agent_port", 9876),
    }
    return cfg


@app.get("/agent/uninstall.sh")
async def uninstall_sh():
    """Serve the uninstall script."""
    import pathlib
    script_path = pathlib.Path(__file__).parent.parent / "uninstall.sh"
    if script_path.exists():
        return FileResponse(script_path, media_type="text/plain")
    return JSONResponse({"error": "uninstall.sh not found"}, 404)


@app.get("/cleanup.sh")
async def cleanup_sh():
    """Serve the cleanup script."""
    import pathlib
    script_path = pathlib.Path(__file__).parent.parent / "cleanup.sh"
    if script_path.exists():
        return FileResponse(script_path, media_type="text/plain")
    return JSONResponse({"error": "cleanup.sh not found"}, 404)


@app.get("/agent/install.sh")
async def install_sh():
    """Serve the install script."""
    import pathlib
    script_path = pathlib.Path(__file__).parent.parent / "install.sh"
    if script_path.exists():
        return FileResponse(script_path, media_type="text/plain")
    return JSONResponse({"error": "install.sh not found"}, 404)


@app.get("/agent/install-cn.sh")
async def install_cn_sh():
    """Serve the CN-friendly install script (no GitHub deps)."""
    import pathlib
    script_path = pathlib.Path(__file__).parent.parent / "install-cn.sh"
    if script_path.exists():
        return FileResponse(script_path, media_type="text/plain")
    return JSONResponse({"error": "install-cn.sh not found"}, 404)


@app.get("/agent/agent.py")
async def agent_py():
    """Serve the agent script."""
    import pathlib
    agent_path = pathlib.Path(__file__).parent.parent / "agent" / "agent.py"
    if agent_path.exists():
        return FileResponse(agent_path, media_type="text/plain")
    return JSONResponse({"error": "agent.py not found"}, 404)


@app.get("/agent/bin/{name}")
async def agent_bin(name: str):
    """Serve pre-downloaded gost/sing-box binaries (CN mirror)."""
    import pathlib
    # Security: only allow known binary names
    allowed = {"gost-linux-amd64.tar.gz", "gost-linux-arm64.tar.gz",
               "sing-box-amd64.tar.gz", "sing-box-arm64.tar.gz"}
    if name not in allowed:
        return JSONResponse({"error": "unknown binary"}, 404)
    bin_path = pathlib.Path(__file__).parent.parent / "agent" / "bin" / name
    if bin_path.exists():
        return FileResponse(bin_path)
    return JSONResponse({"error": f"{name} not found on mirror"}, 404)


# ── Frontend ──────────────────────────────────────────────────────────────
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def index():
    """Serve the SPA frontend."""
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    return JSONResponse({"message": "TransetPanel API", "docs": "/docs"})
