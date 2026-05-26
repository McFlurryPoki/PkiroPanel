"""
Inbound management routes — sing-box inbound CRUD + sync to agent.
"""

import json
import asyncio
from fastapi import APIRouter, HTTPException, Depends
from panel import models
from panel.auth import get_current_user
from panel.ws_handler import manager

router = APIRouter(prefix="/api/inbounds", tags=["inbounds"])


async def _sync_node_inbounds(node_id: str):
    """Background task: push inbound config to a node's agent."""
    try:
        inbounds = await models.list_inbounds_for_node(node_id)
        await manager.send_command(node_id, "singbox.sync", {"inbounds": inbounds})
    except Exception:
        pass


@router.get("")
async def list_inbounds(user: dict = Depends(get_current_user)):
    rows = await models.list_inbounds_for_user(user["id"], user["role"])
    for r in rows:
        r["settings"] = json.loads(r["settings"]) if isinstance(r["settings"], str) else r["settings"]
        r["stream"] = json.loads(r["stream"]) if isinstance(r["stream"], str) else r["stream"]
    return rows


@router.get("/{inbound_id}")
async def get_inbound(inbound_id: str, user: dict = Depends(get_current_user)):
    r = await models.get_inbound(inbound_id)
    if not r:
        raise HTTPException(404, "Inbound not found")
    r["settings"] = json.loads(r["settings"]) if isinstance(r["settings"], str) else r["settings"]
    r["stream"] = json.loads(r["stream"]) if isinstance(r["stream"], str) else r["stream"]
    return r


@router.post("")
async def create_inbound(data: dict, user: dict = Depends(get_current_user)):
    r = await models.create_inbound(data)
    # Auto-assign to default group
    await models.add_inbounds_to_group("default", [r["id"]])
    # Auto-sync to node agent in background
    node_id = data.get("node_id", "")
    if node_id in manager.online_nodes:
        asyncio.create_task(_sync_node_inbounds(node_id))
    return await _build_response(r)


@router.put("/{inbound_id}")
async def update_inbound(inbound_id: str, data: dict, user: dict = Depends(get_current_user)):
    r = await models.update_inbound(inbound_id, data)
    if not r:
        raise HTTPException(404, "Inbound not found")
    node_id = r.get("node_id", "")
    if node_id in manager.online_nodes:
        asyncio.create_task(_sync_node_inbounds(node_id))
    return await _build_response(r)


@router.delete("/{inbound_id}")
async def delete_inbound(inbound_id: str, user: dict = Depends(get_current_user)):
    r = await models.get_inbound(inbound_id)
    node_id = r["node_id"] if r else ""
    await models.delete_inbound(inbound_id)
    if node_id and node_id in manager.online_nodes:
        asyncio.create_task(_sync_node_inbounds(node_id))
    return {"ok": True}


@router.post("/sync/{node_id}")
async def sync_inbounds(node_id: str, user: dict = Depends(get_current_user)):
    """Push inbound config to a node's agent."""
    node = await models.get_node(node_id)
    if not node:
        raise HTTPException(404, "Node not found")
    await _sync_node_inbounds(node_id)
    return {"ok": True}


# ── Batch operations ────────────────────────────────────────────────────────

@router.post("/batch/delete")
async def batch_delete_inbounds(data: dict, user: dict = Depends(get_current_user)):
    ids = data.get("ids", [])
    if not ids:
        raise HTTPException(400, "No inbound IDs provided")
    count = await models.batch_delete_inbounds(ids)
    # Sync affected nodes
    affected_nodes = set()
    for iid in ids:
        r = await models.get_inbound(iid)
        if r:
            affected_nodes.add(r["node_id"])
    for nid in affected_nodes:
        if nid in manager.online_nodes:
            asyncio.create_task(_sync_node_inbounds(nid))
    await models.add_audit("inbounds_batch_deleted", "inbound", "", f"{count} inbounds")
    return {"ok": True, "deleted": count}


@router.post("/batch/group")
async def batch_group_inbounds(data: dict, user: dict = Depends(get_current_user)):
    inbound_ids = data.get("ids", [])
    group_id = data.get("group_id")
    action = data.get("action", "add")
    if not inbound_ids or not group_id:
        raise HTTPException(400, "Missing ids or group_id")
    if action == "add":
        await models.add_inbounds_to_group(group_id, inbound_ids)
    else:
        await models.remove_inbounds_from_group(group_id, inbound_ids)
    await models.add_audit("inbounds_batch_group", "inbound", group_id, f"{action} {len(inbound_ids)} inbounds")
    return {"ok": True}


async def _build_response(r):
    """Parse JSON fields from an inbound dict. Accepts dict or coroutine."""
    import inspect
    if inspect.iscoroutine(r):
        r = await r
    if isinstance(r, dict):
        r["settings"] = json.loads(r["settings"]) if isinstance(r["settings"], str) else r["settings"]
        r["stream"] = json.loads(r["stream"]) if isinstance(r["stream"], str) else r["stream"]
    return r
