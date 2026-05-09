from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .database import SessionLocal
from .models import Check, Workspace
from .notifications import notify_check_red
from .ws import ws_broadcast

logger = logging.getLogger(__name__)

ARUBA_POLL_INTERVAL = 300  # seconds between Central polls per workspace


def _status_for_check(check: Check, now: datetime) -> str:
    if check.last_reported_at is None:
        return "unknown"
    age = now - check.last_reported_at
    timeout = timedelta(minutes=check.timeout_minutes)
    if age < timeout:
        return "green"
    if age < timeout * 2:
        return "yellow"
    return "red"


async def _refresh_aruba_token(cfg: dict, session) -> str | None:
    """Try OAuth2 client-credentials refresh. Returns new access_token or None."""
    try:
        import httpx
        token_url = cfg.get("cluster_url", "").rstrip("/") + "/oauth2/token"
        async with httpx.AsyncClient(verify=False) as client:
            resp = await asyncio.wait_for(
                client.post(
                    token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": cfg.get("client_id", ""),
                        "client_secret": cfg.get("client_secret", ""),
                    },
                ),
                timeout=15,
            )
        if resp.status_code == 200:
            return resp.json().get("access_token")
    except Exception as exc:
        logger.warning("Aruba token refresh failed: %s", exc)
    return None


async def _poll_workspace(workspace: Workspace, db) -> None:
    """Poll Aruba Central for a single workspace and update check last_reported_at."""
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed — Aruba polling unavailable")
        return

    cfg: dict = json.loads(workspace.aruba_config or "{}")
    cluster_url = cfg.get("cluster_url", "").rstrip("/")
    access_token = cfg.get("access_token", "")

    if not cluster_url or not access_token:
        return

    # Fetch checks for this workspace
    checks = db.scalars(
        select(Check).where(Check.workspace_id == workspace.id)
    ).all()
    if not checks:
        return

    check_names: set[str] = {c.check_name.lower() for c in checks}
    headers = {"Authorization": f"Bearer {access_token}"}
    matched: set[str] = set()
    now = datetime.utcnow()

    async def _fetch_alerts(hdrs: dict) -> list[dict]:
        """Try v1 then v2 alerts endpoint."""
        for path in ["/monitoring/v1/alerts", "/monitoring/v2/alerts"]:
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    resp = await asyncio.wait_for(
                        client.get(f"{cluster_url}{path}", headers=hdrs, params={"limit": 1000}),
                        timeout=20,
                    )
                if resp.status_code == 200:
                    return resp.json().get("alerts", [])
                if resp.status_code == 404:
                    continue
                if resp.status_code == 401:
                    return None  # signal 401
            except Exception as exc:
                logger.warning("Aruba alerts fetch error (%s): %s", path, exc)
        return []

    alerts = await _fetch_alerts(headers)

    # Handle 401 — try refresh
    if alerts is None:
        new_token = await _refresh_aruba_token(cfg, db)
        if new_token:
            cfg["access_token"] = new_token
            workspace.aruba_config = json.dumps(cfg)
            db.commit()
            headers = {"Authorization": f"Bearer {new_token}"}
            alerts = await _fetch_alerts(headers) or []
        else:
            logger.warning("workspace %s: Aruba token refresh failed — skipping poll", workspace.name)
            return

    # Match alert names against monitored checks
    for alert in alerts:
        alert_type = (alert.get("alert_type") or alert.get("type") or "").lower()
        alert_name = (alert.get("alert_name") or alert.get("name") or alert_type).lower()
        for name in (alert_type, alert_name):
            if name and name in check_names:
                matched.add(name)

    # Also try insights endpoint
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await asyncio.wait_for(
                client.get(f"{cluster_url}/monitoring/v1/insights", headers=headers, params={"limit": 1000}),
                timeout=20,
            )
        if resp.status_code == 200:
            for insight in resp.json().get("insights", []):
                itype = (insight.get("type") or "").lower()
                iname = (insight.get("name") or itype).lower()
                for name in (itype, iname):
                    if name and name in check_names:
                        matched.add(name)
    except Exception:
        pass

    # Update last_reported_at for matched checks
    if matched:
        for check in checks:
            if check.check_name.lower() in matched:
                check.last_reported_at = now
        db.commit()
        logger.info(
            "workspace %s: confirmed %d checks (%s)",
            workspace.name, len(matched), ", ".join(sorted(matched)),
        )


async def aruba_central_poller() -> None:
    """Background task: poll Aruba Central for all remote-owned workspaces."""
    try:
        while True:
            try:
                with SessionLocal() as db:
                    workspaces = db.scalars(
                        select(Workspace).where(
                            Workspace.central_poll_enabled.is_(True),
                            Workspace.ownership == "remote",
                        )
                    ).all()
                    for workspace in workspaces:
                        await _poll_workspace(workspace, db)
                    if workspaces:
                        logger.info("aruba_poller: polled %d workspace(s)", len(workspaces))
            except Exception:
                logger.exception("aruba_poller: tick failed")

            await asyncio.sleep(ARUBA_POLL_INTERVAL)
    except asyncio.CancelledError:
        logger.info("aruba_poller: stopped")
        raise


async def check_state_engine() -> None:
    try:
        while True:
            try:
                with SessionLocal() as db:
                    now = datetime.utcnow()
                    checks = db.scalars(
                        select(Check).options(selectinload(Check.workspace)).order_by(Check.created_at.asc())
                    ).all()
                    red_transitions: list[tuple[object, Check]] = []

                    for check in checks:
                        previous_status = check.status
                        check.status = _status_for_check(check, now)
                        if check.status == "red" and previous_status != "red" and check.workspace is not None:
                            red_transitions.append((check.workspace, check))

                    db.commit()

                    for workspace, check in red_transitions:
                        await notify_check_red(workspace, check)

                    for check in checks:
                        await ws_broadcast(
                            {
                                "type": "check_update",
                                "workspace_id": str(check.workspace_id),
                                "check_name": check.check_name,
                                "status": check.status,
                            }
                        )

                    logger.info("check_engine: tick — %s checks evaluated", len(checks))
            except Exception:
                logger.exception("check_engine: tick failed")

            await asyncio.sleep(60)
    except asyncio.CancelledError:
        logger.info("check_engine: stopped")
        raise
