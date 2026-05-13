from __future__ import annotations

import asyncio
import json
from typing import Set

from fastapi import WebSocket

browser_connections: Set[WebSocket] = set()
spoke_connections: dict[tuple[str, str], WebSocket] = {}
_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _main_loop
    _main_loop = loop


async def ws_connect(websocket: WebSocket) -> None:
    await websocket.accept()
    browser_connections.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        browser_connections.discard(websocket)


async def register_spoke(websocket: WebSocket, tenant_id: str, spoke_id: str) -> None:
    await websocket.accept()
    spoke_connections[(tenant_id, spoke_id)] = websocket


async def unregister_spoke(tenant_id: str, spoke_id: str, websocket: WebSocket | None = None) -> None:
    current = spoke_connections.get((tenant_id, spoke_id))
    if websocket is None or current is websocket:
        spoke_connections.pop((tenant_id, spoke_id), None)


async def ws_broadcast(data: dict) -> None:
    dead = set()
    message = json.dumps(data)
    for ws in tuple(browser_connections):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    browser_connections.difference_update(dead)


async def push_spoke_commands(tenant_id: str, spoke_id: str) -> bool:
    websocket = spoke_connections.get((tenant_id, spoke_id))
    if websocket is None:
        return False

    from . import store

    commands = store.peek_queued_commands(tenant_id, spoke_id)
    if not commands:
        return True

    payload = {
        "type": "commands",
        "commands": [
            {"id": c.id, "target": c.target, "type": c.type, "payload": c.payload}
            for c in commands
        ],
    }
    try:
        await websocket.send_json(payload)
    except Exception:
        await unregister_spoke(tenant_id, spoke_id, websocket)
        return False

    store.mark_commands_delivered(tenant_id, spoke_id, [command.id for command in commands])
    return True


def notify_spoke_command(tenant_id: str, spoke_id: str) -> None:
    if _main_loop is None:
        return
    asyncio.run_coroutine_threadsafe(push_spoke_commands(tenant_id, spoke_id), _main_loop)
