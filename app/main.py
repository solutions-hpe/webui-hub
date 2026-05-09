import asyncio
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, WebSocket
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import auth
from .database import Base, engine
from .routers import auth as auth_router
from .routers import checks, commands, islands, sites, workspaces
from .tasks import check_state_engine
from .ws import ws_connect

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    auth.ensure_admin()
    check_engine_task = asyncio.create_task(check_state_engine())
    try:
        yield
    finally:
        check_engine_task.cancel()
        with suppress(asyncio.CancelledError):
            await check_engine_task


app = FastAPI(title="Client-Sim Central", lifespan=lifespan)
app.include_router(islands.router, prefix="/api/islands", tags=["islands"])
app.include_router(sites.router, prefix="/api/sites", tags=["sites"])
app.include_router(workspaces.router, tags=["workspaces"])
app.include_router(commands.router, prefix="/api/commands", tags=["commands"])
app.include_router(checks.router, prefix="/api/checks", tags=["checks"])
app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_connect(websocket)


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    return FileResponse(STATIC_DIR / "index.html")
