from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .database import SessionLocal
from .models import Check
from .notifications import notify_check_red
from .ws import ws_broadcast

logger = logging.getLogger(__name__)


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
