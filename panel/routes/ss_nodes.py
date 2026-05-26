"""SS2022 node management routes."""

from fastapi import APIRouter, HTTPException
from panel import models
from panel.ws_handler import manager

router = APIRouter(prefix="/api/ss", tags=["ss_nodes"])


@router.get("")
async def list_ss_nodes(node_id: str = None):
    return await models.list_ss_nodes(node_id)


@router.post("")
async def create_ss_node(data: dict):
    required = ["node_id", "port", "password"]
    for f in required:
        if f not in data:
            raise HTTPException(400, f"Missing required field: {f}")
    ss = await models.create_ss_node(data)
    await models.add_audit("ss_created", "ss_node", ss["id"],
                           f"port {data['port']} on {data['node_id']}")

    # Push config to agent if online
    node_id = data["node_id"]
    if node_id in manager.online_nodes:
        await manager.send_command(node_id, "ss.sync", {"ss_node": ss})

    return ss


@router.put("/{ss_id}")
async def update_ss_node(ss_id: str, data: dict):
    await models.update_ss_node(ss_id, data)
    await models.add_audit("ss_updated", "ss_node", ss_id)
    return {"ok": True}


@router.delete("/{ss_id}")
async def delete_ss_node(ss_id: str):
    await models.delete_ss_node(ss_id)
    await models.add_audit("ss_deleted", "ss_node", ss_id)
    return {"ok": True}
