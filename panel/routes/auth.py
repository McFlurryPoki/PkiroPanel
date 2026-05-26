"""Auth and user management routes."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from panel import models as m
from panel.auth import create_token, get_current_user, require_admin

router = APIRouter(prefix="/api/auth", tags=["auth"])
users_router = APIRouter(prefix="/api/users", tags=["users"])


# ── Pydantic schemas ───────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    password: str = Field(min_length=6, max_length=64)


class UpdateProfileRequest(BaseModel):
    username: str | None = Field(default=None, min_length=2, max_length=32)
    display_name: str | None = Field(default=None, max_length=64)
    avatar_url: str | None = Field(default=None, max_length=512)


# ── Auth routes ────────────────────────────────────────────────────────────

@router.post("/login")
async def login(body: LoginRequest):
    user = await m.get_user_by_username(body.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    stored = user["password_hash"]
    if ":" not in stored:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    salt, pw_hash = stored.split(":", 1)
    if not m.verify_password(body.password, salt, pw_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(user["id"], user["username"], user["role"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user.get("display_name", ""),
            "avatar_url": user.get("avatar_url", ""),
            "role": user["role"]
        }
    }


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    full = await m.get_user_by_id(user["id"])
    if full:
        user["display_name"] = full.get("display_name", "")
        user["avatar_url"] = full.get("avatar_url", "")
    return {"user": user}


@router.post("/change-password")
async def change_password(body: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    full = await m.get_user_by_username(user["username"])
    if not full:
        raise HTTPException(status_code=404)

    stored = full["password_hash"]
    salt, pw_hash = stored.split(":", 1)
    if not m.verify_password(body.old_password, salt, pw_hash):
        raise HTTPException(status_code=401, detail="Old password is wrong")

    await m.change_password(user["id"], body.new_password)
    return {"message": "Password changed"}


@router.post("/profile")
async def update_profile(body: UpdateProfileRequest, user: dict = Depends(get_current_user)):
    updates = {}
    if body.username is not None:
        existing = await m.get_user_by_username(body.username)
        if existing and existing["id"] != user["id"]:
            raise HTTPException(status_code=409, detail="Username already exists")
        updates["username"] = body.username
    if body.display_name is not None:
        updates["display_name"] = body.display_name
    if body.avatar_url is not None:
        updates["avatar_url"] = body.avatar_url

    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")

    updated = await m.update_profile(user["id"], **updates)
    return {"user": updated}




class UpdateRoleRequest(BaseModel):
    role: str = Field(pattern="^(admin|user)$")


@users_router.put("/{user_id}/role")
async def update_user_role(user_id: int, body: UpdateRoleRequest, user: dict = Depends(get_current_user)):
    """Update a user's role (admin only)."""
    require_admin(user)
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    ok = await m.update_user_role(user_id, body.role)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Role updated"}


# ── User management ────────────────────────────────────────────────────────

@users_router.get("")
async def list_users(user: dict = Depends(get_current_user)):
    return {"users": await m.list_users()}


@users_router.post("")
async def create_user(body: CreateUserRequest, user: dict = Depends(get_current_user)):
    existing = await m.get_user_by_username(body.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    new_user = await m.create_user(body.username, body.password)
    return {"user": new_user}


@users_router.get("/{user_id}/groups")
async def get_user_groups(user_id: int, user: dict = Depends(get_current_user)):
    gids = await m.get_user_groups(user_id)
    return {"groups": gids}

@users_router.delete("/{user_id}")
async def delete_user(user_id: int, user: dict = Depends(get_current_user)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    ok = await m.delete_user(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted"}


# ── User Group Traffic Limits ────────────────────────────────────────────────

class TrafficLimitRequest(BaseModel):
    group_id: str
    traffic_limit_bytes: int = 0


@users_router.get("/{user_id}/traffic-limits")
async def get_traffic_limits(user_id: int, user: dict = Depends(get_current_user)):
    return await m.get_user_group_traffic_limits(user_id)


@users_router.put("/{user_id}/traffic-limits")
async def set_traffic_limit(user_id: int, body: TrafficLimitRequest, user: dict = Depends(get_current_user)):
    require_admin(user)
    await m.set_user_group_traffic_limit(user_id, body.group_id, body.traffic_limit_bytes)
    return {"ok": True}


@users_router.get("/{user_id}/traffic-limits/{group_id}/check")
async def check_quota(user_id: int, group_id: str, user: dict = Depends(get_current_user)):
    over, used, limit = await m.check_user_group_quota(user_id, group_id)
    return {"over_quota": over, "used_bytes": used, "limit_bytes": limit}
