"""Forward management routes (gost edition)."""

from fastapi import APIRouter, HTTPException, Depends
from panel import models
from panel.auth import get_current_user
from panel.ws_handler import manager
import asyncio

router = APIRouter(prefix="/api/forwards", tags=["forwards"])


@router.get("")
async def list_forwards(node_id: str = None, user: dict = Depends(get_current_user)):
    return await models.list_forwards_for_user(user["id"], user["role"], node_id)


@router.post("")
async def create_forward(data: dict, user: dict = Depends(get_current_user)):
    required = ["node_id", "listen_addr", "remote_addr"]
    for f in required:
        if f not in data:
            raise HTTPException(400, f"Missing required field: {f}")
    fwd = await models.create_forward(data)
    await models.add_audit("forward_created", "forward", fwd["id"],
                           f"{data['listen_addr']} -> {data['remote_addr']}")

    # Push ALL forwards for this node to agent if online
    node_id = data["node_id"]
    if node_id in manager.online_nodes:
        node_forwards = await models.list_forwards(node_id)
        await manager.send_command(node_id, "gost.sync", {"forwards": node_forwards})

    return fwd


@router.post("/tunnel")
async def create_tunnel(data: dict, user: dict = Depends(get_current_user)):
    required = ["entry_node_id", "exit_node_id", "landing_addr",
                "listen_port", "tunnel_port"]
    for f in required:
        if f not in data:
            raise HTTPException(400, f"Missing required field: {f}")

    try:
        fwds = await models.create_tunnel_forwards(
            entry_node_id=data["entry_node_id"],
            exit_node_id=data["exit_node_id"],
            landing_addr=data["landing_addr"],
            listen_port=int(data["listen_port"]),
            tunnel_port=int(data["tunnel_port"]),
            tls_mode=data.get("tls_mode", "tls"),
            rate_limit=int(data.get("rate_limit", 0)),
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    await models.add_audit("tunnel_created", "tunnel", fwds[0]["tunnel_id"],
                           f"entry→exit→landing ({fwds[0]['listen_addr']} → {fwds[1]['remote_addr']})")

    # Push ALL configs to each unique node
    synced_nodes = set()
    for fwd in fwds:
        nid = fwd["node_id"]
        if nid not in synced_nodes and nid in manager.online_nodes:
            node_forwards = await models.list_forwards(nid)
            await manager.send_command(nid, "gost.sync", {"forwards": node_forwards})
            synced_nodes.add(nid)

    # For WG tunnels, also sync WireGuard config to both nodes
    if data.get("tls_mode") == "wg":
        for nid in [data["entry_node_id"], data["exit_node_id"]]:
            if nid in manager.online_nodes:
                node = await models.get_node(nid)
                peers = await models.get_wg_peers(nid)
                wg_ip = ""
                for p in peers:
                    if p.get("wg_ip"):
                        wg_ip = p["wg_ip"]
                        break
                wg_port = 51820
                await manager.send_command(nid, "wg.sync", {
                    "private_key": node.get("wg_private_key", ""),
                    "peers": peers,
                    "wg_ip": wg_ip,
                    "listen_port": wg_port,
                })

    return {"tunnel_id": fwds[0]["tunnel_id"], "forwards": fwds}


@router.put("/{fwd_id}")
async def update_forward(fwd_id: str, data: dict, user: dict = Depends(get_current_user)):
    await models.update_forward(fwd_id, data)
    await models.add_audit("forward_updated", "forward", fwd_id)
    return {"ok": True}


@router.delete("/{fwd_id}")
async def delete_forward(fwd_id: str, user: dict = Depends(get_current_user)):
    await models.delete_forward(fwd_id)
    await models.add_audit("forward_deleted", "forward", fwd_id)
    return {"ok": True}


@router.delete("/tunnel/{tunnel_id}")
async def delete_tunnel(tunnel_id: str, user: dict = Depends(get_current_user)):
    """Delete all forwards in a tunnel + clean up WG resources."""
    all_fwds = await models.list_forwards()
    tunnel_fwds = [f for f in all_fwds if f.get("tunnel_id") == tunnel_id]

    for f in tunnel_fwds:
        await models.delete_forward(f["id"])

    # Clean up WG tunnel records + notify nodes to tear down WG
    is_wg = any(f.get("tls_mode") == "wg" for f in tunnel_fwds)
    if is_wg:
        from panel.models import get_db
        db = await get_db()
        for f in tunnel_fwds:
            await db.execute("DELETE FROM wg_tunnels WHERE entry_node_id = ? OR exit_node_id = ?",
                             (f["node_id"], f["node_id"]))
        await db.commit()

        done = set()
        for f in tunnel_fwds:
            if f["node_id"] not in done and f["node_id"] in manager.online_nodes:
                await manager.send_command(f["node_id"], "wg.sync", {
                    "private_key": "", "peers": [], "wg_ip": "", "listen_port": 51820
                })
                done.add(f["node_id"])

    await models.add_audit("tunnel_deleted", "tunnel", tunnel_id)
    return {"ok": True, "deleted": len(tunnel_fwds)}


# ── Batch operations ────────────────────────────────────────────────────────

@router.post("/batch/delete")
async def batch_delete_forwards(data: dict, user: dict = Depends(get_current_user)):
    ids = data.get("ids", [])
    if not ids:
        raise HTTPException(400, "No forward IDs provided")
    count = await models.batch_delete_forwards(ids)
    await models.add_audit("forwards_batch_deleted", "forward", "", f"{count} forwards")
    return {"ok": True, "deleted": count}


@router.post("/batch/replace-entry")
async def batch_replace_entry(data: dict, user: dict = Depends(get_current_user)):
    """Replace entry node for selected tunnel forwards."""
    forward_ids = data.get("ids", [])
    new_entry_node_id = data["new_entry_node_id"]
    new_listen_port = data.get("new_listen_port")
    if not forward_ids or not new_entry_node_id:
        raise HTTPException(400, "Missing ids or new_entry_node_id")
    count = await models.batch_replace_forwards_entry(forward_ids, new_entry_node_id, new_listen_port)
    # Sync affected nodes
    affected_nodes = set()
    for fwd_id in forward_ids:
        cursor = await (await models.get_db()).execute("SELECT node_id FROM forwards WHERE id=?", (fwd_id,))
        row = await cursor.fetchone()
        if row:
            affected_nodes.add(row["node_id"])
    for nid in affected_nodes:
        if nid in manager.online_nodes:
            node_forwards = await models.list_forwards(nid)
            asyncio.create_task(manager.send_command(nid, "gost.sync", {"forwards": node_forwards}))
    await models.add_audit("forwards_batch_replace_entry", "forward", new_entry_node_id, f"{count} forwards")
    return {"ok": True, "updated": count}


@router.post("/batch/replace-exit")
async def batch_replace_exit(data: dict, user: dict = Depends(get_current_user)):
    """Replace exit node for selected tunnel forwards."""
    forward_ids = data.get("ids", [])
    new_exit_node_id = data["new_exit_node_id"]
    if not forward_ids or not new_exit_node_id:
        raise HTTPException(400, "Missing ids or new_exit_node_id")
    count = await models.batch_replace_forwards_exit(forward_ids, new_exit_node_id)
    affected_nodes = set()
    for fwd_id in forward_ids:
        cursor = await (await models.get_db()).execute("SELECT node_id FROM forwards WHERE id=?", (fwd_id,))
        row = await cursor.fetchone()
        if row:
            affected_nodes.add(row["node_id"])
    for nid in affected_nodes:
        if nid in manager.online_nodes:
            node_forwards = await models.list_forwards(nid)
            asyncio.create_task(manager.send_command(nid, "gost.sync", {"forwards": node_forwards}))
    await models.add_audit("forwards_batch_replace_exit", "forward", new_exit_node_id, f"{count} forwards")
    return {"ok": True, "updated": count}


# ── TCP ping ────────────────────────────────────────────────────────────────

@router.post("/{fwd_id}/tcping")
async def tcping_forward(fwd_id: str, user: dict = Depends(get_current_user)):
    """TCP ping the remote address of a forward rule via the node's agent."""
    forwards_list = await models.list_forwards()
    fwd = next((f for f in forwards_list if f["id"] == fwd_id), None)
    if not fwd:
        raise HTTPException(404, "Forward not found")
    
    node_id = fwd["node_id"]
    if node_id not in manager.online_nodes:
        raise HTTPException(503, "Node offline")
    
    host, port = fwd["remote_addr"].rsplit(":", 1)
    result1 = await manager.send_command(node_id, "tcping", {
        "host": host,
        "port": int(port),
        "count": 5,
        "timeout": 3.0,
    }, timeout=20)
    
    if result1.get("error"):
        raise HTTPException(500, result1["error"])
    
    output = result1.get("stdout", "")
    
    if fwd.get("forward_type") == "tunnel" and fwd.get("tunnel_id"):
        transit_fwd = next(
            (f for f in forwards_list 
             if f["tunnel_id"] == fwd["tunnel_id"] and f["id"] != fwd_id),
            None
        )
        if transit_fwd and transit_fwd["node_id"] in manager.online_nodes:
            thost, tport = transit_fwd["remote_addr"].rsplit(":", 1)
            result2 = await manager.send_command(transit_fwd["node_id"], "tcping", {
                "host": thost,
                "port": int(tport),
                "count": 5,
                "timeout": 3.0,
            }, timeout=20)
            
            if not result2.get("error"):
                output += "\n" + result2.get("stdout", "")
    
    return {"result": {"stdout": output}}
