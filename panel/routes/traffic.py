"""Traffic management routes."""

import time
from fastapi import APIRouter, HTTPException
from panel import models
from panel.database import get_db

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


@router.get("/summary")
async def get_traffic_summary():
    summaries = await models.get_traffic_summary()
    result = []
    for node_id, s in summaries.items():
        node = await models.get_node(node_id)
        result.append({
            "node_id": node_id,
            "node_name": node["name"] if node else node_id,
            "node_type": node["type"] if node else "unknown",
            **s
        })
    return result


@router.post("/reset/{node_id}")
async def reset_traffic(node_id: str):
    await models.reset_traffic(node_id)
    await models.add_audit("traffic_reset", "node", node_id)
    return {"ok": True}


@router.post("/reset-all")
async def reset_all_traffic():
    nodes = await models.list_nodes()
    for n in nodes:
        await models.reset_traffic(n["id"])
    await models.add_audit("traffic_reset_all")
    return {"ok": True, "count": len(nodes)}


@router.put("/config/{node_id}")
async def update_traffic_config(node_id: str, data: dict):
    """Update traffic limits and/or current usage for a node."""
    db = await get_db()

    # Update limits + reset_day if provided
    await db.execute(
        """INSERT INTO traffic_summary (node_id, period_limit_rx, period_limit_tx, reset_day)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(node_id) DO UPDATE SET
           period_limit_rx = COALESCE(?, period_limit_rx),
           period_limit_tx = COALESCE(?, period_limit_tx),
           reset_day = COALESCE(?, reset_day)""",
        (node_id, data.get("period_limit_rx", 0), data.get("period_limit_tx", 0),
         data.get("reset_day", 1), data.get("period_limit_rx"),
         data.get("period_limit_tx"), data.get("reset_day"))
    )

    # Update current usage if provided (for correcting mid-cycle addition)
    if "period_rx_bytes" in data or "period_tx_bytes" in data:
        fields = []
        values = []
        if "period_rx_bytes" in data:
            fields.append("period_rx_bytes = ?")
            values.append(data["period_rx_bytes"])
        if "period_tx_bytes" in data:
            fields.append("period_tx_bytes = ?")
            values.append(data["period_tx_bytes"])
        values.append(node_id)
        await db.execute(f"UPDATE traffic_summary SET {', '.join(fields)} WHERE node_id = ?", values)

    await db.commit()
    return {"ok": True}
