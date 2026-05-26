"""WebSocket handler for agent communication."""

import asyncio
import json
import time
from fastapi import WebSocket, WebSocketDisconnect
from panel import models

SECRET_KEY = __import__("os").environ.get("SECRET_KEY", "change-me-in-production")


class ConnectionManager:
    """Manages WebSocket connections from agents."""

    def __init__(self):
        self.agents: dict[str, dict] = {}       # node_id -> {ws, info}
        self.pending: dict[str, asyncio.Future] = {}  # cmd_id -> Future

    async def connect(self, ws: WebSocket):
        await ws.accept()

        # Wait for auth
        try:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=10)
            msg = json.loads(raw)
        except asyncio.TimeoutError:
            print(f"[WS] auth timeout from {ws.client.host}")
            await ws.close(4001, "auth timeout")
            return None
        except json.JSONDecodeError as e:
            print(f"[WS] bad JSON from {ws.client.host}: {e}")
            await ws.close(4001, "bad json")
            return None

        if msg.get("type") != "auth":
            print(f"[WS] bad auth type from {ws.client.host}: {msg.get('type')}")
            await ws.send_json({"type": "auth_fail", "reason": "expected auth"})
            await ws.close(4003, "bad auth")
            return None

        node_id = msg.get("node_id")
        token = msg.get("token")
        expected = SECRET_KEY[:32]
        print(f"[WS] auth attempt: node={node_id} from={ws.client.host} token_len={len(token or '')} expected_len={len(expected)}")

        # Simple token check
        if token != expected:
            print(f"[WS] AUTH FAIL: node={node_id} token mismatch")
            await ws.send_json({"type": "auth_fail", "reason": "bad token"})
            await ws.close(4003, "bad token")
            return None

        # Update node status
        now = time.time()
        agent_info = msg.get("agent", {})
        await models.update_node(node_id, {
            "status": "online",
            "agent_version": agent_info.get("version", "unknown"),
            "os_info": agent_info.get("os", "unknown"),
            "last_seen": now,
            "agent_deployed": 1,
        })

        self.agents[node_id] = {"ws": ws, "info": agent_info,
                                "connected_at": now, "last_seen": now}
        await ws.send_json({"type": "auth_ok", "server_time": now})
        print(f"[WS] AUTH OK: node={node_id} from={ws.client.host}")
        await models.add_audit("agent_connected", "node", node_id)

        return node_id

    async def disconnect(self, node_id: str):
        if node_id in self.agents:
            del self.agents[node_id]
            await models.update_node(node_id, {"status": "offline"})
            print(f"[WS] DISCONNECT: node={node_id}")
            await models.add_audit("agent_disconnected", "node", node_id)

    async def handle_agent(self, ws: WebSocket, node_id: str):
        """Main agent message loop."""
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                if msg.get("type") == "status_report":
                    stats = msg.get("stats", {})
                    net_rx = stats.get("net_rx_bytes", 0)
                    net_tx = stats.get("net_tx_bytes", 0)

                    try:
                        # Save stats
                        await models.save_node_stats(node_id, stats)

                        # Update last_seen in DB so health check doesn't mark offline
                        await models.update_node(node_id, {"last_seen": time.time()})

                        # Update traffic (only for transit nodes, but tracked globally too)
                        prev_rx = self.agents[node_id].get("prev_rx", 0)
                        prev_tx = self.agents[node_id].get("prev_tx", 0)
                        if prev_rx > 0 and net_rx > prev_rx:
                            await models.add_traffic(node_id, net_rx - prev_rx, net_tx - prev_tx)
                        self.agents[node_id]["prev_rx"] = net_rx
                        self.agents[node_id]["prev_tx"] = net_tx
                    except Exception as e:
                        print(f"[WS] stats save error for {node_id}: {e}")
                        # If FK error (node doesn't exist), disconnect gracefully
                        if "FOREIGN KEY" in str(e).upper():
                            await ws.close(4000, "node not found")
                            break

                    self.agents[node_id]["last_seen"] = time.time()

                elif msg.get("type") == "result":
                    cmd_id = msg.get("id")
                    if cmd_id and cmd_id in self.pending:
                        self.pending[cmd_id].set_result(msg.get("data", {}))

                elif msg.get("type") == "heartbeat":
                    self.agents[node_id]["last_seen"] = time.time()
                    await models.update_node(node_id, {"last_seen": time.time()})

        except WebSocketDisconnect:
            print(f"[WS] handle_agent WebSocketDisconnect: node={node_id}")
            pass
        except Exception as e:
            print(f"[WS] handle_agent error: node={node_id} err={e}")
            pass
        finally:
            await self.disconnect(node_id)

    async def send_command(self, node_id: str, action: str, params: dict = None,
                           timeout: int = 30) -> dict:
        """Send a command to agent and wait for result."""
        if node_id not in self.agents:
            return {"error": "agent not connected"}

        import uuid
        cmd_id = uuid.uuid4().hex[:8]
        future = asyncio.get_running_loop().create_future()
        self.pending[cmd_id] = future

        try:
            await self.agents[node_id]["ws"].send_json({
                "type": "cmd",
                "id": cmd_id,
                "action": action,
                "params": params or {},
            })
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            return {"error": "timeout"}
        finally:
            self.pending.pop(cmd_id, None)

    def get_node_status(self, node_id: str) -> dict | None:
        if node_id in self.agents:
            return {
                "connected": True,
                "last_seen": self.agents[node_id].get("last_seen"),
                "info": self.agents[node_id].get("info"),
            }
        return None

    @property
    def online_nodes(self) -> list[str]:
        return list(self.agents.keys())


manager = ConnectionManager()
