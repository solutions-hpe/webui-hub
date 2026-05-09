from fastapi import WebSocket
from typing import Set
import asyncio

connected: Set[WebSocket] = set()


async def ws_connect(websocket: WebSocket):
    await websocket.accept()
    connected.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        connected.discard(websocket)


async def ws_broadcast(data: dict):
    import json

    dead = set()
    for ws in tuple(connected):
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.add(ws)
    connected.difference_update(dead)
