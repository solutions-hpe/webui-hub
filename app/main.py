from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import store
from .auth import ensure_admin
from .config import get_settings
from .ws import set_main_loop, ws_connect

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
TEMPLATE_DIR = FRONTEND_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store.init_store()
    ensure_admin()
    set_main_loop(asyncio.get_running_loop())
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


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_connect(websocket)


from .routers import auth as auth_router
from .routers import aggregate, backups, checks, commands, settings as settings_router, sites, spokes, superadmin, workspaces

app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(spokes.router, prefix="/api", tags=["spokes"])
app.include_router(sites.router, prefix="/api", tags=["sites"])
app.include_router(superadmin.router, prefix="/api", tags=["superadmin"])
app.include_router(workspaces.router, prefix="/api", tags=["workspaces"])
app.include_router(checks.router, prefix="/api", tags=["checks"])
app.include_router(commands.router, prefix="/api", tags=["commands"])
app.include_router(settings_router.router, prefix="/api", tags=["settings"])
app.include_router(aggregate.router, prefix="/api", tags=["aggregate"])
app.include_router(backups.router, prefix="/api", tags=["backups"])


@app.get("/api/health")
def health():
    import os
    from pathlib import Path
    sha = os.getenv("APP_VERSION", "dev")
    branch = os.getenv("APP_BRANCH", "local")
    short = sha[:7] if len(sha) > 7 else sha
    version_file = Path(__file__).resolve().parent.parent / "VERSION"
    app_version = version_file.read_text().strip() if version_file.exists() else short
    return {"status": "ok", "version": app_version, "branch": branch, "sha": sha}


@app.get("/api/init")
# intentionally unauthenticated; returns only {"mode": "hub"}
def api_init():
    return {"mode": "hub"}


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa_fallback(full_path: str):
    index = TEMPLATE_DIR / "index.html"
    try:
        html = index.read_text()
        version_file = Path(__file__).resolve().parent.parent / "VERSION"
        ver = version_file.read_text().strip() if version_file.exists() else "dev"
        html = html.replace('href="/static/style.css"', f'href="/static/style.css?v={ver}"')
        html = html.replace('src="/static/app.js"', f'src="/static/app.js?v={ver}"')
        return HTMLResponse(content=html)
    except FileNotFoundError:
        logger.error("index.html not found at %s — frontend may not be built", index)
        raise HTTPException(status_code=503, detail="Frontend not available. Check hub deployment.")
    except OSError as exc:
        logger.error("Failed to read index.html: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read frontend.")
