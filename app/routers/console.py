from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import ssl
import time
import urllib.parse
import uuid
from typing import Any

import httpx
import websockets
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from starlette.websockets import WebSocketState

from .. import auth, store, ws as relay_ws
from ..crypto import decrypt_str
from ..data_models import User

router = APIRouter()
logger = logging.getLogger(__name__)

_sessions: dict[str, dict[str, Any]] = {}
SESSION_TTL = 60
SHELL_START_TIMEOUT = 10
_CONNECT_HEADER_ARG = (
    "additional_headers"
    if "additional_headers" in inspect.signature(websockets.connect).parameters
    else "extra_headers"
)


def _cleanup_sessions() -> None:
    now = time.time()
    expired = [key for key, value in _sessions.items() if value.get("expires", 0) < now]
    for key in expired:
        _sessions.pop(key, None)


def _proxmox_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"PVEAPIToken={token}"}


def _proxmox_error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("message") or payload.get("error")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        errors = payload.get("errors")
        if isinstance(errors, dict) and errors:
            return "; ".join(f"{key}: {value}" for key, value in errors.items())
    text = response.text.strip()
    return text or f"HTTP {response.status_code}"


def _resolve_spoke_node(spoke) -> str:
    telemetry = spoke.telemetry if isinstance(spoke.telemetry, dict) else {}
    proxmox = telemetry.get("proxmox") if isinstance(telemetry.get("proxmox"), dict) else {}
    proxmox_node = proxmox.get("node") if isinstance(proxmox.get("node"), dict) else {}
    node = telemetry.get("node") if isinstance(telemetry.get("node"), dict) else {}
    candidates = [
        node.get("hostname"),
        proxmox_node.get("hostname"),
        spoke.hostname,
    ]
    for candidate in candidates:
        value = str(candidate or "").strip()
        if value:
            return value
    return ""


def _require_tenant_admin(tenant_id: str, user: User) -> None:
    auth.require_tenant_member(tenant_id, user)
    if user.get_role(tenant_id) != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


async def _close_shell_websocket(websocket: WebSocket, code: int, reason: str) -> None:
    if websocket.application_state != WebSocketState.DISCONNECTED:
        await websocket.close(code=code, reason=reason)


async def _browser_to_spoke_shell(websocket: WebSocket, tenant_id: str, spoke_id: str, session_id: str) -> None:
    while True:
        message = await websocket.receive_json()
        if not isinstance(message, dict):
            raise ValueError("Shell websocket payload must be a JSON object")
        msg_type = str(message.get("type") or "").strip().lower()
        if msg_type == "shell_input":
            if not await relay_ws.send_to_spoke(tenant_id, spoke_id, {
                "type": "shell_input",
                "session_id": session_id,
                "data": str(message.get("data") or ""),
            }):
                raise RuntimeError("Spoke relay disconnected")
        elif msg_type == "shell_resize":
            cols = int(message.get("cols") or 80)
            rows = int(message.get("rows") or 24)
            if not await relay_ws.send_to_spoke(tenant_id, spoke_id, {
                "type": "shell_resize",
                "session_id": session_id,
                "cols": cols,
                "rows": rows,
            }):
                raise RuntimeError("Spoke relay disconnected")


async def _spoke_to_browser_shell(websocket: WebSocket, queue: asyncio.Queue, session_id: str) -> None:
    while True:
        message = await queue.get()
        if not isinstance(message, dict) or message.get("session_id") != session_id:
            continue
        await websocket.send_json(message)
        if str(message.get("type") or "") == "shell_exit":
            return


async def _request_vnc_proxy(
    *,
    proxmox_host: str,
    proxmox_token: str,
    node: str,
    vmid: int,
    vmtype: str,
) -> dict[str, Any]:
    path = f"/api2/json/nodes/{urllib.parse.quote(node, safe='')}/{vmtype}/{vmid}/vncproxy"
    url = f"https://{proxmox_host}:8006{path}"
    async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
        response = await client.post(
            url,
            headers=_proxmox_headers(proxmox_token),
            data={"websocket": 1},
        )
    if not response.is_success:
        raise HTTPException(status_code=502, detail=_proxmox_error_message(response))
    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Invalid response from Proxmox vncproxy") from exc
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Missing Proxmox vncproxy response data")
    ticket = str(data.get("ticket") or "").strip()
    port = data.get("port")
    if not ticket or port is None:
        raise HTTPException(status_code=502, detail="Proxmox vncproxy did not return ticket and port")
    return {"ticket": ticket, "port": int(port)}


async def _browser_to_proxmox(websocket: WebSocket, upstream) -> None:
    while True:
        message = await websocket.receive()
        message_type = message.get("type")
        if message_type == "websocket.disconnect":
            raise WebSocketDisconnect(code=message.get("code", 1000))
        if message_type != "websocket.receive":
            continue
        if message.get("bytes") is not None:
            await upstream.send(message["bytes"])
        elif message.get("text") is not None:
            await upstream.send(message["text"])


async def _proxmox_to_browser(upstream, websocket: WebSocket) -> None:
    while True:
        message = await upstream.recv()
        if isinstance(message, bytes):
            await websocket.send_bytes(message)
        else:
            await websocket.send_text(message)


@router.get("/console", response_class=HTMLResponse, include_in_schema=False)
async def vnc_console_page(session_id: str = Query(...), token: str = Query(...)):
    """Serve the noVNC console page for a given console session."""
    html = _VNC_PAGE_HTML.replace("__SESSION_ID__", session_id).replace("__AUTH_TOKEN__", token)
    return HTMLResponse(content=html)


_VNC_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VM Console</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    html, body { width: 100%; height: 100%; background: #1a1a2e; overflow: hidden; }
    #toolbar {
      display: flex; align-items: center; gap: 10px;
      padding: 6px 12px; background: #16213e; border-bottom: 1px solid #333;
      color: #ccc; font-family: sans-serif; font-size: 13px;
    }
    #toolbar button {
      padding: 4px 12px; border: 1px solid #555; border-radius: 4px;
      background: #0f3460; color: #eee; cursor: pointer; font-size: 12px;
    }
    #toolbar button:hover { background: #1a5276; }
    #status { margin-left: auto; font-size: 12px; }
    #status.connected { color: #2ecc71; }
    #status.disconnected { color: #e74c3c; }
    #status.connecting { color: #f39c12; }
    #screen { width: 100%; height: calc(100vh - 38px); }
    #screen canvas { width: 100% !important; height: 100% !important; }
  </style>
</head>
<body>
  <div id="toolbar">
    <strong>VM Console</strong>
    <button onclick="sendCtrlAltDel()">Ctrl+Alt+Del</button>
    <button onclick="toggleClipboard()">Clipboard</button>
    <button onclick="rfb && rfb.sendKey(0xFFE9, 'AltLeft', true); rfb && rfb.sendKey(0xFFE9, 'AltLeft', false);" style="display:none" id="btn-extra"></button>
    <span id="status" class="connecting">Connecting…</span>
  </div>
  <div id="screen"></div>
  <script type="module">
    import RFB from 'https://cdn.jsdelivr.net/npm/@novnc/novnc@1.4.0/core/rfb.js';

    const sessionId = '__SESSION_ID__';
    const authToken = '__AUTH_TOKEN__';
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = proto + '//' + location.host + '/ws/console/' + sessionId + '?token=' + encodeURIComponent(authToken);

    const statusEl = document.getElementById('status');
    let rfb;

    function setStatus(msg, cls) {
      statusEl.textContent = msg;
      statusEl.className = cls;
    }

    try {
      rfb = new RFB(document.getElementById('screen'), wsUrl, {
        credentials: { password: '' },
      });

      rfb.scaleViewport = true;
      rfb.resizeSession = false;

      rfb.addEventListener('connect', () => setStatus('Connected', 'connected'));
      rfb.addEventListener('disconnect', (e) => {
        const reason = e.detail?.reason || 'Connection closed';
        setStatus('Disconnected: ' + reason, 'disconnected');
      });
      rfb.addEventListener('credentialsrequired', () => {
        const pass = prompt('VNC Password:') || '';
        rfb.sendCredentials({ password: pass });
      });
      rfb.addEventListener('securityfailure', (e) => {
        setStatus('Security failure: ' + (e.detail?.reason || 'unknown'), 'disconnected');
      });
    } catch (err) {
      setStatus('Error: ' + err.message, 'disconnected');
    }

    window.rfb = rfb;
    window.sendCtrlAltDel = () => rfb && rfb.sendCtrlAltDel();
    window.toggleClipboard = () => {
      if (!rfb) return;
      if (document.fullscreenElement) document.exitFullscreen();
      else document.getElementById('screen').requestFullscreen().catch(() => {});
    };
  </script>
</body>
</html>"""


@router.post("/api/{tenant_id}/spokes/{spoke_id}/console/{vmid}")
async def create_console_session(
    tenant_id: str,
    spoke_id: str,
    vmid: int,
    vmtype: str = Query("qemu"),
    current_user: User = Depends(auth.get_current_user),
):
    auth.require_tenant_member(tenant_id, current_user)
    _cleanup_sessions()
    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        raise HTTPException(status_code=404, detail="Spoke not found")
    if spoke.status != "approved":
        raise HTTPException(status_code=409, detail="Spoke is not approved")

    normalized_vmtype = str(vmtype or "qemu").strip().lower()
    if normalized_vmtype not in {"qemu", "lxc"}:
        raise HTTPException(status_code=400, detail="vmtype must be qemu or lxc")

    token_enc = str(getattr(spoke, "proxmox_token_enc", "") or "").strip()
    if not token_enc:
        raise HTTPException(status_code=400, detail="Configure Proxmox credentials first.")
    try:
        proxmox_token = decrypt_str(token_enc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to decrypt Proxmox credentials") from exc

    node = _resolve_spoke_node(spoke)
    if not node:
        raise HTTPException(status_code=400, detail="Spoke telemetry is missing the Proxmox node hostname")

    proxmox_host = str(getattr(spoke, "proxmox_host", "") or "").strip() or str(spoke.hostname or "").strip()
    if not proxmox_host:
        raise HTTPException(status_code=400, detail="Spoke is missing a Proxmox host")

    proxy = await _request_vnc_proxy(
        proxmox_host=proxmox_host,
        proxmox_token=proxmox_token,
        node=node,
        vmid=vmid,
        vmtype=normalized_vmtype,
    )

    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "tenant_id": tenant_id,
        "spoke_id": spoke_id,
        "vmid": vmid,
        "vmtype": normalized_vmtype,
        "node": node,
        "ticket": proxy["ticket"],
        "port": proxy["port"],
        "proxmox_host": proxmox_host,
        "proxmox_token": proxmox_token,
        "expires": time.time() + SESSION_TTL,
    }
    return {"session_id": session_id, "expires_in": SESSION_TTL}


@router.websocket("/ws/console/{session_id}")
async def console_websocket(websocket: WebSocket, session_id: str, token: str = Query(...)):
    _cleanup_sessions()
    session = _sessions.get(session_id)
    if not session or session.get("expires", 0) < time.time():
        await websocket.close(code=4404, reason="Invalid or expired console session")
        return

    try:
        user = auth.decode_access_token(str(token or "").strip())
        auth.require_tenant_member(session["tenant_id"], user)
    except HTTPException as exc:
        code = 4401 if exc.status_code == 401 else 4403
        await websocket.close(code=code, reason=str(exc.detail))
        return

    _sessions.pop(session_id, None)
    await websocket.accept()

    params = urllib.parse.urlencode(
        {
            "port": session["port"],
            "vncticket": session["ticket"],
        }
    )
    path = (
        f"/api2/json/nodes/{urllib.parse.quote(session['node'], safe='')}/"
        f"{session['vmtype']}/{session['vmid']}/vncwebsocket?{params}"
    )
    upstream_url = f"wss://{session['proxmox_host']}:8006{path}"

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    connect_kwargs: dict[str, Any] = {
        "ssl": ssl_context,
        "open_timeout": 20,
        "max_size": None,
        _CONNECT_HEADER_ARG: _proxmox_headers(session["proxmox_token"]),
    }

    upstream = None
    relay_tasks: list[asyncio.Task[Any]] = []
    try:
        async with websockets.connect(upstream_url, **connect_kwargs) as upstream:
            relay_tasks = [
                asyncio.create_task(_browser_to_proxmox(websocket, upstream)),
                asyncio.create_task(_proxmox_to_browser(upstream, websocket)),
            ]
            done, pending = await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*relay_tasks, return_exceptions=True)
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (WebSocketDisconnect, websockets.ConnectionClosed)):
                    raise exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Console relay failed for session %s: %s", session_id, exc)
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.close(code=1011, reason="Console relay failed")
    finally:
        for task in relay_tasks:
            if not task.done():
                task.cancel()
        if relay_tasks:
            await asyncio.gather(*relay_tasks, return_exceptions=True)
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.close()


@router.websocket("/api/{tenant_id}/spokes/{spoke_id}/shell")
async def spoke_shell_ws(websocket: WebSocket, tenant_id: str, spoke_id: str, token: str = Query(...)):
    try:
        current_user = auth.decode_access_token(str(token or "").strip())
        _require_tenant_admin(tenant_id, current_user)
    except HTTPException as exc:
        await websocket.close(code=4401 if exc.status_code == 401 else 4403, reason=str(exc.detail))
        return

    spoke = store.get_spoke(tenant_id, spoke_id)
    if not spoke:
        await websocket.close(code=4404, reason="Spoke not found")
        return
    if spoke.status != "approved":
        await websocket.close(code=4409, reason="Spoke is not approved")
        return

    session_id = str(uuid.uuid4())
    queue = relay_ws.register_shell_session(session_id)
    relay_tasks: list[asyncio.Task[Any]] = []
    browser_disconnected = False

    await websocket.accept()
    try:
        sent = await relay_ws.send_to_spoke(tenant_id, spoke_id, {"type": "shell_start", "session_id": session_id})
        if not sent:
            await websocket.send_json({"type": "shell_exit", "session_id": session_id, "exit_code": -1, "error": "Spoke relay is offline"})
            await _close_shell_websocket(websocket, 1011, "Spoke relay is offline")
            return

        try:
            started_message = await asyncio.wait_for(queue.get(), timeout=SHELL_START_TIMEOUT)
        except asyncio.TimeoutError:
            await websocket.send_json({"type": "shell_exit", "session_id": session_id, "exit_code": -1, "error": "Timed out waiting for shell startup"})
            with contextlib.suppress(Exception):
                await relay_ws.send_to_spoke(tenant_id, spoke_id, {"type": "shell_exit", "session_id": session_id})
            await _close_shell_websocket(websocket, 1011, "Shell startup timeout")
            return

        if not isinstance(started_message, dict):
            raise RuntimeError("Invalid shell startup response")

        started_type = str(started_message.get("type") or "")
        await websocket.send_json(started_message)
        if started_type != "shell_started":
            await _close_shell_websocket(websocket, 1011, str(started_message.get("error") or "Shell startup failed"))
            return

        relay_tasks = [
            asyncio.create_task(_browser_to_spoke_shell(websocket, tenant_id, spoke_id, session_id)),
            asyncio.create_task(_spoke_to_browser_shell(websocket, queue, session_id)),
        ]
        done, pending = await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*relay_tasks, return_exceptions=True)
        for task in done:
            exc = task.exception()
            if isinstance(exc, WebSocketDisconnect):
                browser_disconnected = True
                continue
            if exc and not isinstance(exc, asyncio.CancelledError):
                raise exc
    except WebSocketDisconnect:
        browser_disconnected = True
    except Exception as exc:
        logger.warning("Spoke shell relay failed for %s/%s session %s: %s", tenant_id, spoke_id, session_id, exc)
        if websocket.application_state != WebSocketState.DISCONNECTED:
            with contextlib.suppress(Exception):
                await websocket.send_json({"type": "shell_exit", "session_id": session_id, "exit_code": -1, "error": str(exc)})
            await _close_shell_websocket(websocket, 1011, "Shell relay failed")
    finally:
        relay_ws.unregister_shell_session(session_id)
        for task in relay_tasks:
            if not task.done():
                task.cancel()
        if relay_tasks:
            await asyncio.gather(*relay_tasks, return_exceptions=True)
        if browser_disconnected:
            with contextlib.suppress(Exception):
                await relay_ws.send_to_spoke(tenant_id, spoke_id, {"type": "shell_exit", "session_id": session_id})
        if websocket.application_state != WebSocketState.DISCONNECTED:
            await websocket.close()
