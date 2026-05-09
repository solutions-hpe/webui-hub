from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import auth
from .database import Base, engine
from .routers import auth as auth_router
from .routers import checks, commands, islands, sites, workspaces

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    auth.ensure_admin()
    yield


app = FastAPI(title="Client-Sim Central", lifespan=lifespan)
app.include_router(islands.router, prefix="/api/islands", tags=["islands"])
app.include_router(sites.router, prefix="/api/sites", tags=["sites"])
app.include_router(workspaces.router, prefix="/api/workspaces", tags=["workspaces"])
app.include_router(commands.router, prefix="/api/commands", tags=["commands"])
app.include_router(checks.router, prefix="/api/checks", tags=["checks"])
app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    return FileResponse(STATIC_DIR / "index.html")
