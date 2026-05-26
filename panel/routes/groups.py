"""Group management routes — CRUD, membership, user authorization."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from panel import models
from panel.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/groups", tags=["groups"])


# ── Pydantic models ────────────────────────────────────────────────────────

class CreateGroupRequest(BaseModel):
    name: str
    description: str = ""

class UpdateGroupRequest(BaseModel):
    name: str = None
    description: str = None

class BatchIdsRequest(BaseModel):
    ids: list[str]

class GroupUsersRequest(BaseModel):
    user_ids: list[int]


# ── CRUD ───────────────────────────────────────────────────────────────────

@router.get("")
async def list_groups(user: dict = Depends(get_current_user)):
    """Admins see all groups; regular users see only groups they belong to."""
    if user["role"] == "admin":
        groups = await models.list_groups()
    else:
        gids = await models.get_user_groups(user["id"])
        all_groups = await models.list_groups()
        groups = [g for g in all_groups if g["id"] in gids]
    return groups


@router.post("")
async def create_group(body: CreateGroupRequest, user: dict = Depends(require_admin)):
    grp = await models.create_group(body.name, body.description)
    await models.add_audit("group_created", "group", grp["id"], body.name)
    return grp


@router.put("/{group_id}")
async def update_group(group_id: str, body: UpdateGroupRequest, user: dict = Depends(require_admin)):
    grp = await models.get_group(group_id)
    if not grp:
        raise HTTPException(404, "Group not found")
    grp = await models.update_group(group_id, body.name, body.description)
    await models.add_audit("group_updated", "group", group_id)
    return grp


@router.delete("/{group_id}")
async def delete_group(group_id: str, user: dict = Depends(require_admin)):
    if group_id == "default":
        raise HTTPException(400, "Cannot delete default group")
    await models.delete_group(group_id)
    await models.add_audit("group_deleted", "group", group_id)
    return {"ok": True}


# ── Node membership ────────────────────────────────────────────────────────

@router.get("/{group_id}/nodes")
async def list_group_nodes(group_id: str, user: dict = Depends(get_current_user)):
    return await models.get_group_nodes(group_id)


@router.post("/{group_id}/nodes")
async def add_group_nodes(group_id: str, body: BatchIdsRequest, user: dict = Depends(require_admin)):
    await models.add_nodes_to_group(group_id, body.ids)
    await models.add_audit("group_nodes_added", "group", group_id, f"+{len(body.ids)} nodes")
    return {"ok": True, "added": len(body.ids)}


@router.delete("/{group_id}/nodes")
async def remove_group_nodes(group_id: str, body: BatchIdsRequest, user: dict = Depends(require_admin)):
    await models.remove_nodes_from_group(group_id, body.ids)
    await models.add_audit("group_nodes_removed", "group", group_id, f"-{len(body.ids)} nodes")
    return {"ok": True, "removed": len(body.ids)}


# ── Inbound membership ─────────────────────────────────────────────────────

@router.get("/{group_id}/inbounds")
async def list_group_inbounds(group_id: str, user: dict = Depends(get_current_user)):
    return await models.get_group_inbounds(group_id)


@router.post("/{group_id}/inbounds")
async def add_group_inbounds(group_id: str, body: BatchIdsRequest, user: dict = Depends(require_admin)):
    await models.add_inbounds_to_group(group_id, body.ids)
    await models.add_audit("group_inbounds_added", "group", group_id, f"+{len(body.ids)} inbounds")
    return {"ok": True, "added": len(body.ids)}


@router.delete("/{group_id}/inbounds")
async def remove_group_inbounds(group_id: str, body: BatchIdsRequest, user: dict = Depends(require_admin)):
    await models.remove_inbounds_from_group(group_id, body.ids)
    await models.add_audit("group_inbounds_removed", "group", group_id, f"-{len(body.ids)} inbounds")
    return {"ok": True, "removed": len(body.ids)}


# ── User authorization ─────────────────────────────────────────────────────

@router.get("/{group_id}/users")
async def list_group_users(group_id: str, user: dict = Depends(get_current_user)):
    return await models.get_group_users(group_id)


@router.put("/{group_id}/users")
async def set_group_users(group_id: str, body: GroupUsersRequest, user: dict = Depends(require_admin)):
    await models.set_group_users(group_id, body.user_ids)
    await models.add_audit("group_users_set", "group", group_id, f"{len(body.user_ids)} users")
    return {"ok": True}
# ── Group Node Limits ────────────────────────────────────────────────────────

class NodeLimitRequest(BaseModel):
    node_id: str
    rate_limit_kbps: int = 0


@router.get("/{group_id}/node-limits")
async def get_node_limits(group_id: str, user: dict = Depends(get_current_user)):
    return await models.get_group_node_limits(group_id)


@router.put("/{group_id}/node-limits")
async def set_node_limit(group_id: str, body: NodeLimitRequest, user: dict = Depends(require_admin)):
    await models.set_group_node_limit(group_id, body.node_id, body.rate_limit_kbps)
    return {"ok": True}


# ── Group Node Limits ────────────────────────────────────────────────────────

class NodeLimitRequest(BaseModel):
    node_id: str
    rate_limit_kbps: int = 0


@router.get("/{group_id}/node-limits")
async def get_node_limits(group_id: str, user: dict = Depends(get_current_user)):
    return await models.get_group_node_limits(group_id)


@router.put("/{group_id}/node-limits")
async def set_node_limit(group_id: str, body: NodeLimitRequest, user: dict = Depends(require_admin)):
    await models.set_group_node_limit(group_id, body.node_id, body.rate_limit_kbps)
    return {"ok": True}
