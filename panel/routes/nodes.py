"""Node management routes."""

import json
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import StreamingResponse
from panel import models
from panel.auth import get_current_user
from panel.crypto_utils import encrypt, decrypt, mask_password
from panel.deployer import deployer
from panel.ws_handler import manager
import asyncio

router = APIRouter(prefix="/api/nodes", tags=["nodes"])


@router.get("")
async def list_nodes(user: dict = Depends(get_current_user)):
    nodes = await models.list_nodes_for_user(user["id"], user["role"])
    for n in nodes:
        if n.get("ssh_password"):
            n["ssh_password_masked"] = mask_password(decrypt(n["ssh_password"]))
            n["ssh_password"] = None
        # Add live status from WS
        ws_status = manager.get_node_status(n["id"])
        if ws_status:
            n["ws_connected"] = ws_status["connected"]
            n["agent_info"] = ws_status.get("info")
    return nodes


@router.post("")
async def create_node(data: dict, user: dict = Depends(get_current_user)):
    required = ["name", "type", "host"]
    for f in required:
        if f not in data:
            raise HTTPException(400, f"Missing required field: {f}")
    # Encrypt SSH password if provided
    if data.get("ssh_password"):
        data["ssh_password"] = encrypt(data["ssh_password"])
    node = await models.create_node(data)
    # Auto-assign to default group
    await models.add_nodes_to_group("default", [node["id"]])
    await models.add_audit("node_created", "node", node["id"], data.get("name"))
    return node


@router.put("/{node_id}")
async def update_node(node_id: str, data: dict, user: dict = Depends(get_current_user)):
    node = await models.get_node(node_id)
    if not node:
        raise HTTPException(404, "Node not found")
    if data.get("ssh_password"):
        data["ssh_password"] = encrypt(data["ssh_password"])
    await models.update_node(node_id, data)
    await models.add_audit("node_updated", "node", node_id)
    return {"ok": True}


@router.delete("/{node_id}")
async def delete_node(node_id: str, user: dict = Depends(get_current_user)):
    node = await models.get_node(node_id)
    if not node:
        raise HTTPException(404, "Node not found")
    await models.delete_node(node_id)
    # Optionally sync to agent to clean up
    if node_id in manager.online_nodes:
        await manager.send_command(node_id, "gost.sync", {"forwards": []})
    await models.add_audit("node_deleted", "node", node_id, node.get("name"))
    return {"ok": True}


# ── Batch operations ────────────────────────────────────────────────────────

@router.post("/batch/delete")
async def batch_delete_nodes(data: dict, user: dict = Depends(get_current_user)):
    ids = data.get("ids", [])
    if not ids:
        raise HTTPException(400, "No node IDs provided")
    count = await models.batch_delete_nodes(ids)
    # Sync any online nodes
    for nid in ids:
        if nid in manager.online_nodes:
            await manager.send_command(nid, "gost.sync", {"forwards": []})
    await models.add_audit("nodes_batch_deleted", "node", "", f"{count} nodes")
    return {"ok": True, "deleted": count}


@router.post("/batch/group")
async def batch_group_nodes(data: dict, user: dict = Depends(get_current_user)):
    node_ids = data.get("ids", [])
    group_id = data.get("group_id")
    action = data.get("action", "add")  # "add" or "remove"
    if not node_ids or not group_id:
        raise HTTPException(400, "Missing ids or group_id")
    if action == "add":
        await models.add_nodes_to_group(group_id, node_ids)
    else:
        await models.remove_nodes_from_group(group_id, node_ids)
    await models.add_audit("nodes_batch_group", "node", group_id, f"{action} {len(node_ids)} nodes")
    return {"ok": True}


# ── Deploy / stats / traffic / commands ────────────────────────────────────

@router.post("/{node_id}/deploy")
async def deploy_agent(node_id: str, user: dict = Depends(get_current_user)):
    node = await models.get_node(node_id)
    if not node:
        raise HTTPException(404, "Node not found")
    if not node.get("ssh_password"):
        raise HTTPException(400, "Node has no SSH credentials")
    if node_id in deployer.active_deployments:
        raise HTTPException(400, "Deployment already in progress")

    await models.update_node(node_id, {"agent_deployed": 2})
    log_queue = await deployer.deploy(node)
    return {"ok": True, "node_id": node_id}


@router.get("/{node_id}/deploy/log")
async def deploy_log(node_id: str, request: Request, user: dict = Depends(get_current_user)):
    """SSE stream for deployment logs."""
    log_queue = deployer.get_log_queue(node_id)
    if not log_queue:
        return StreamingResponse(
            iter(["data: No deployment in progress\n\n"]),
            media_type="text/event-stream"
        )

    async def stream():
        while True:
            if await request.is_disconnected():
                break
            try:
                msg = await asyncio.wait_for(log_queue.get(), timeout=30)
                if msg == "__CLOSE__":
                    deployer.remove_deployment(node_id)
                    break
                if msg == "__SUCCESS__":
                    await models.update_node(node_id, {"agent_deployed": 1})
                    yield f"data: {json.dumps({'type': 'success', 'msg': 'Deployment complete'})}\n\n"
                    break
                if msg and msg.startswith("__ERROR__"):
                    await models.update_node(node_id, {"agent_deployed": 0})
                    yield f"data: {json.dumps({'type': 'error', 'msg': msg[9:]})}\n\n"
                    deployer.remove_deployment(node_id)
                    break
                yield f"data: {json.dumps({'type': 'log', 'msg': msg})}\n\n"
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.get("/{node_id}/stats")
async def get_node_stats(node_id: str, hours: int = 24, user: dict = Depends(get_current_user)):
    return await models.get_node_stats(node_id, hours)


@router.get("/{node_id}/traffic")
async def get_node_traffic(node_id: str, user: dict = Depends(get_current_user)):
    summaries = await models.get_traffic_summary()
    return summaries.get(node_id, {})


@router.post("/{node_id}/cmd")
async def send_node_command(node_id: str, data: dict, user: dict = Depends(get_current_user)):
    """Send a command to the agent on this node."""
    action = data.get("action")
    if not action:
        raise HTTPException(400, "Missing action")
    result = await manager.send_command(node_id, action, data.get("params", {}),
                                        data.get("timeout", 30))
    return result
