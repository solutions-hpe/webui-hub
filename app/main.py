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
SHARED_DIR = BASE_DIR / "shared"


_SENTINEL_FILE = Path(get_settings().data_dir) / ".keycheck"
_SENTINEL_VALUE = "hub-key-ok"


def _run_key_health_check() -> None:
    """Verify the encryption key is consistent between restarts.

    On first run: encrypt a sentinel string and write it to .keycheck.
    On subsequent runs: decrypt the sentinel and compare to the expected value.
    If the sentinel cannot be decrypted (key changed or corrupted), log a
    CRITICAL warning but continue — the hub can still operate, existing
    encrypted configs will just fail to decrypt.
    """
    from .crypto import decrypt_str, encrypt_str

    try:
        if _SENTINEL_FILE.exists():
            ciphertext = _SENTINEL_FILE.read_text().strip()
            try:
                plaintext = decrypt_str(ciphertext)
                if plaintext == _SENTINEL_VALUE:
                    logger.info("Key health check: WEBUI_SECRET_KEY verified ✓")
                else:
                    logger.critical(
                        "Key health check FAILED: decrypted sentinel mismatch — "
                        "WEBUI_SECRET_KEY may have changed. Existing encrypted configs will be unreadable."
                    )
            except Exception as exc:
                logger.critical(
                    "Key health check FAILED: cannot decrypt sentinel — "
                    "WEBUI_SECRET_KEY may have changed or be wrong: %s. "
                    "Existing encrypted configs will be unreadable.",
                    exc,
                )
        else:
            # First run — write the sentinel
            _SENTINEL_FILE.parent.mkdir(parents=True, exist_ok=True)
            _SENTINEL_FILE.write_text(encrypt_str(_SENTINEL_VALUE))
            logger.info("Key health check: sentinel written (first run) ✓")
    except Exception as exc:
        logger.warning("Key health check skipped (mount not ready?): %s", exc)


_VERSION_FILE = BASE_DIR / "VERSION"
_LAST_HUB_VERSION_FILE = Path(get_settings().data_dir) / ".last_hub_version"


def _trigger_spoke_updates_on_hub_upgrade() -> None:
    """If the hub VERSION changed since last startup, queue spoke + proxmox
    agent self-updates for all approved spokes across all tenants."""
    current = _VERSION_FILE.read_text().strip() if _VERSION_FILE.exists() else "unknown"
    try:
        _LAST_HUB_VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        last = _LAST_HUB_VERSION_FILE.read_text().strip() if _LAST_HUB_VERSION_FILE.exists() else None
    except Exception:
        last = None

    if last == current:
        logger.info("Hub version unchanged (%s) — no automatic spoke updates queued", current)
        return

    logger.info(
        "Hub upgraded %s → %s — queuing spoke and agent updates for all tenants",
        last or "(first run)",
        current,
    )
    _LAST_HUB_VERSION_FILE.write_text(current)

    if last is None:
        # First run — record version but don't push updates; spokes are fresh
        return

    from .data_models import Command
    from datetime import timedelta, timezone
    from datetime import datetime
    import uuid

    now = datetime.now(timezone.utc)
    tenants = store.list_tenants()
    queued = 0
    for tenant in tenants:
        spokes = [s for s in store.list_spokes(tenant.id) if s.status == "approved"]
        for spoke in spokes:
            expires = now + timedelta(hours=24)
            store.enqueue_command(Command(
                spoke_id=spoke.id,
                tenant_id=tenant.id,
                type="proxmox_agent_update",
                payload={},
                expires_at=expires,
            ))
            store.enqueue_command(Command(
                spoke_id=spoke.id,
                tenant_id=tenant.id,
                type="self_update",
                payload={},
                expires_at=expires,
            ))
            queued += 2
    logger.info("Hub upgrade: queued %d update commands across %d tenants", queued, len(tenants))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store.init_store()
    ensure_admin()
    _run_key_health_check()
    _trigger_spoke_updates_on_hub_upgrade()
    set_main_loop(asyncio.get_running_loop())
    logger.info(f"Hub starting — data dir: {settings.data_dir}")

    from . import tasks

    bg_tasks = [
        asyncio.create_task(tasks.gkill_switch_poller()),
        asyncio.create_task(tasks.heartbeat_monitor()),
        asyncio.create_task(tasks.auto_recovery_check()),
        asyncio.create_task(tasks.schedule_check()),
        asyncio.create_task(tasks.aruba_poller()),
        asyncio.create_task(tasks.hub_baseline_saver()),
        asyncio.create_task(tasks.check_state_engine()),
        asyncio.create_task(tasks.maintenance_loop()),
        asyncio.create_task(tasks.acme_renewal_check()),
        asyncio.create_task(tasks.central_browse_poller()),
        asyncio.create_task(tasks.loop_lag_monitor()),
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
app.mount("/shared", StaticFiles(directory=str(SHARED_DIR)), name="shared")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_connect(websocket)


from .routers import auth as auth_router
from .routers import aggregate, backups, checks, commands, console, qa as qa_router, settings as settings_router, sites, spokes, superadmin, webhook, workspaces
from .routers import t3 as t3_router

app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(qa_router.router, prefix="/api", tags=["qa"])
app.include_router(console.router, tags=["console"])
app.include_router(spokes.router, prefix="/api", tags=["spokes"])
app.include_router(sites.router, prefix="/api", tags=["sites"])
app.include_router(superadmin.router, prefix="/api", tags=["superadmin"])
app.include_router(workspaces.router, prefix="/api", tags=["workspaces"])
app.include_router(checks.router, prefix="/api", tags=["checks"])
app.include_router(commands.router, prefix="/api", tags=["commands"])
app.include_router(settings_router.router, prefix="/api", tags=["settings"])
app.include_router(aggregate.router, prefix="/api", tags=["aggregate"])
app.include_router(webhook.router)
app.include_router(backups.router, prefix="/api", tags=["backups"])
app.include_router(t3_router.router, prefix="/api", tags=["t3"])


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
# intentionally unauthenticated
def api_init():
    base = Path(__file__).resolve().parent.parent
    semver_file = base / "frontend" / "SEMVER"
    client_sim_file = base / "CLIENT_SIM_VERSION"
    app_version = semver_file.read_text().strip() if semver_file.exists() else "1.00"
    installer_version = client_sim_file.read_text().strip() if client_sim_file.exists() else "1.00"
    return {"mode": "hub", "app_version": app_version, "installer_version": installer_version}


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa_fallback(full_path: str):
    index = TEMPLATE_DIR / "index.html"
    try:
        html = index.read_text()
        version_file = Path(__file__).resolve().parent.parent / "VERSION"
        ver = version_file.read_text().strip() if version_file.exists() else "dev"
        html = html.replace('href="/static/style.css"', f'href="/static/style.css?v={ver}"')
        html = html.replace('src="/static/app.js"', f'src="/static/app.js?v={ver}"')
        html = html.replace('src="/static/js/main.js"', f'src="/static/js/main.js?v={ver}"')
        html = html.replace("'{{WEBUI_MODE}}'", "'hub'")
        html = html.replace("'{{WEBUI_VERSION}}'", f"'{ver}'")
        return HTMLResponse(content=html)
    except FileNotFoundError:
        logger.error("index.html not found at %s — frontend may not be built", index)
        raise HTTPException(status_code=503, detail="Frontend not available. Check hub deployment.")
    except OSError as exc:
        logger.error("Failed to read index.html: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read frontend.")
