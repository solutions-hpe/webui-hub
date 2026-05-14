from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _normalize_notification_config(cfg: dict[str, Any] | None) -> dict[str, Any]:
    data = dict(cfg or {})
    to_emails = data.get("to_emails") or []
    if isinstance(to_emails, str):
        to_emails = [item.strip() for item in to_emails.split(",") if item.strip()]
    teams_webhook = data.get("teams_webhook") or data.get("teams_webhook_url") or ""
    smtp_pass = data.get("smtp_pass")
    if smtp_pass is None:
        smtp_pass = data.get("smtp_password", "")
    return {
        **data,
        "enabled": bool(data.get("enabled")),
        "teams_webhook": teams_webhook,
        "teams_webhook_url": teams_webhook,
        "smtp_pass": smtp_pass or "",
        "to_emails": to_emails,
    }


async def send_teams_webhook(url: str, title: str, message: str, color: str = "FF0000"):
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": title,
        "sections": [{"activityTitle": title, "activityText": message}],
    }
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(url, json=payload)
        except Exception as e:
            logger.warning(f"Teams webhook failed: {e}")


def _send_email_sync(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    from_addr: str,
    to_addrs: list,
    message: str,
) -> None:
    with smtplib.SMTP(smtp_host, smtp_port) as s:
        if smtp_user:
            s.login(smtp_user, smtp_pass)
        s.sendmail(from_addr, to_addrs, message)


async def send_email(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    from_addr: str,
    to_addrs: list,
    subject: str,
    body: str,
):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    try:
        await asyncio.to_thread(
            _send_email_sync,
            smtp_host,
            smtp_port,
            smtp_user,
            smtp_pass,
            from_addr,
            to_addrs,
            msg.as_string(),
        )
    except Exception as e:
        logger.warning(f"Email notification failed: {e}")


def get_notification_config(tenant_id: str) -> dict | None:
    """Get decrypted notification config for a tenant. Returns None if not configured."""
    from . import store
    from .crypto import decrypt_dict

    tenant = store.get_tenant(tenant_id)
    if not tenant or not tenant.notification_config_enc:
        return None
    try:
        cfg = _normalize_notification_config(decrypt_dict(tenant.notification_config_enc))
        return cfg if cfg.get("enabled") else None
    except Exception:
        return None


async def notify_check_red(workspace, check):
    """Fire notifications when a check transitions to red."""
    cfg = {}
    if workspace.notification_config:
        try:
            cfg = _normalize_notification_config(json.loads(workspace.notification_config))
        except Exception:
            pass
    if not cfg.get("enabled"):
        return
    title = f"🔴 Check Failed: {check.check_name}"
    message = (
        f"Workspace **{workspace.name}** — check `{check.check_name}` has gone RED "
        f"(no report in {check.timeout_minutes * 2}min)."
    )
    if cfg.get("teams_webhook"):
        await send_teams_webhook(cfg["teams_webhook"], title, message)
    if cfg.get("smtp_host") and cfg.get("to_emails"):
        await send_email(
            cfg["smtp_host"],
            cfg.get("smtp_port", 587),
            cfg.get("smtp_user", ""),
            cfg.get("smtp_pass", ""),
            cfg.get("from_email", "csw@localhost"),
            cfg["to_emails"],
            title,
            message,
        )
