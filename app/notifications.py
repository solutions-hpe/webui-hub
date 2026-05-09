import httpx, smtplib, json, logging
from email.mime.text import MIMEText
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


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
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            if smtp_user:
                s.login(smtp_user, smtp_pass)
            s.sendmail(from_addr, to_addrs, msg.as_string())
    except Exception as e:
        logger.warning(f"Email notification failed: {e}")


async def notify_check_red(workspace, check):
    """Fire notifications when a check transitions to red."""
    cfg = {}
    if workspace.notification_config:
        try:
            cfg = json.loads(workspace.notification_config)
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
