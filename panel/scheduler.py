"""Scheduler for periodic tasks: traffic reset + health check."""

import asyncio
import time
from datetime import datetime
from panel import models
from panel.ws_handler import manager


async def check_traffic_reset():
    """Check if any nodes need traffic reset based on reset_day."""
    now = datetime.now()
    summaries = await models.get_traffic_summary()
    for node_id, s in summaries.items():
        reset_day = s.get("reset_day", 1)
        if now.day == reset_day:
            # Reset at midnight of reset_day
            await models.reset_traffic(node_id)
            await models.add_audit("traffic_auto_reset", "node", node_id,
                                   f"auto reset on day {reset_day}")


async def check_node_health():
    """Mark nodes offline if agent hasn't reported in > 90 seconds."""
    now = time.time()
    nodes = await models.list_nodes()
    for node in nodes:
        if node.get("status") == "online":
            last_seen = node.get("last_seen", 0)
            if now - last_seen > 90:
                await models.update_node(node["id"], {"status": "offline"})
                await models.add_audit("node_offline", "node", node["id"],
                                       f"no heartbeat for {int(now - last_seen)}s")


async def scheduler_loop():
    """Main scheduler loop."""
    last_reset_check = 0
    last_health_check = 0

    while True:
        now = time.time()

        # Traffic reset check — every hour
        if now - last_reset_check > 3600:
            try:
                await check_traffic_reset()
            except Exception as e:
                print(f"Scheduler: traffic reset error: {e}")
            last_reset_check = now

        # Health check — every 30 seconds
        if now - last_health_check > 30:
            try:
                await check_node_health()
            except Exception as e:
                print(f"Scheduler: health check error: {e}")
            last_health_check = now

        await asyncio.sleep(10)
