from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import store
from .auth import ensure_admin
from .config import get_settings
from .ws import ws_connect

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store.init_store()
    ensure_admin()
    logger.info(f"Hub starting — data dir: {settings.data_dir}")

    from . import tasks

    bg_tasks = [
        asyncio.create_task(tasks.gkill_switch_poller()),
        asyncio.create_task(tasks.heartbeat_monitor()),
        asyncio.create_task(tasks.auto_recovery_check()),
        asyncio.create_task(tasks.schedule_check()),
        asyncio.create_task(tasks.aruba_poller()),
        asyncio.create_task(tasks.check_state_engine()),
        asyncio.create_task(tasks.maintenance_loop()),
        asyncio.create_task(tasks.acme_renewal_check()),
    ]
    try:
        yield
    finally:
        for task in bg_tasks:
            task.cancel()
        for task in bg_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task


app = FastAPI(title="Hub — Client-Sim Central Platform", lifespan=lifespan)
_acme_challenges: dict[str, str] = {}


@app.get("/.well-known/acme-challenge/{token}", include_in_schema=False)
async def acme_http_challenge(token: str):
    key_authorization = _acme_challenges.get(token)
    if not key_authorization:
        raise HTTPException(status_code=404)
    return PlainTextResponse(key_authorization)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_connect(websocket)


from .routers import auth as auth_router
from .routers import checks, commands, islands, settings as settings_router, sites, superadmin, workspaces

app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(islands.router, prefix="/api", tags=["islands"])
app.include_router(sites.router, prefix="/api", tags=["sites"])
app.include_router(superadmin.router, prefix="/api", tags=["superadmin"])
app.include_router(workspaces.router, prefix="/api", tags=["workspaces"])
app.include_router(checks.router, prefix="/api", tags=["checks"])
app.include_router(commands.router, prefix="/api", tags=["commands"])
app.include_router(settings_router.router, prefix="/api", tags=["settings"])


@app.get("/api/health")
def health():
    import os
    sha = os.getenv("APP_VERSION", "dev")
    branch = os.getenv("APP_BRANCH", "local")
    short = sha[:7] if len(sha) > 7 else sha
    return {"status": "ok", "version": short, "branch": branch, "sha": sha}


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    return FileResponse(STATIC_DIR / "index.html")
