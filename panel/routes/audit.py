"""Audit log routes."""

from fastapi import APIRouter
from panel import models

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def list_audit(limit: int = 100):
    return await models.list_audit(limit)
