"""Central webhook event receiver."""
from __future__ import annotations

import logging
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request

from .. import store
from ..aruba import ArubaFinding
from ..crypto import decrypt_dict
from ..tasks import _hub_central_status, _set_hub_central_status
from ..ws import ws_broadcast

router = APIRouter(prefix="/api")
logger = logging.getLogger(__name__)


def _webhook_status_from_payload(payload: dict[str, Any]) -> str:
    if str(payload.get("state") or "").strip().lower() == "cleared":
        return "green"
    severity = str(payload.get("severity") or "").strip().lower()
    if severity in {"critical", "major"}:
        return "red"
    if severity == "minor":
        return "yellow"
    return "green"


def _merge_findings(current: list[dict[str, Any]] | None, webhook_findings: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    merged = [dict(item) for item in (current or []) if isinstance(item, dict)]
    seen = {
        (
            str(item.get("site") or "").strip(),
            str(item.get("check") or "").strip(),
            str(item.get("source") or "").strip(),
        )
        for item in merged
    }
    for item in webhook_findings.values():
        key = (
            str(item.get("site") or "").strip(),
            str(item.get("check") or "").strip(),
            str(item.get("source") or "").strip(),
        )
        if key in seen:
            continue
        merged.append(dict(item))
        seen.add(key)
    return merged


@router.post("/{tenant_id}/webhook/central")
async def receive_central_webhook(
    tenant_id: str,
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    """Receive real-time alert events from HPE Aruba Central."""
    tenant = store.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if not tenant.aruba_config_enc:
        raise HTTPException(status_code=404, detail="Central webhook is not configured")
    try:
        cfg = decrypt_dict(tenant.aruba_config_enc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read Aruba webhook config: {exc}") from exc

    webhook_api_key = str(cfg.get("webhook_api_key") or "").strip()
    if not webhook_api_key:
        raise HTTPException(status_code=404, detail="Central webhook is not configured")
    expected_auth = f"Bearer {webhook_api_key}"
    if not authorization or not secrets.compare_digest(authorization, expected_auth):
        raise HTTPException(status_code=401, detail="Invalid webhook authorization")

    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook payload: {exc}") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object")

    tenant_state = dict(_hub_central_status.get(tenant_id) or {})
    site_id_map = tenant_state.get("site_id_map") if isinstance(tenant_state.get("site_id_map"), dict) else {}
    site_id = str(payload.get("siteId") or "").strip()
    site_name = str(site_id_map.get(site_id) or site_id or "unknown").strip() or "unknown"
    finding = ArubaFinding(
        site_name=site_name,
        check_name=str(payload.get("name") or payload.get("alertId") or payload.get("id") or "alert").strip() or "alert",
        status=_webhook_status_from_payload(payload),
        source="alert",
        raw=payload,
    )
    finding_payload = {
        "site": finding.site_name,
        "check": finding.check_name,
        "status": finding.status,
        "source": finding.source,
        "alert_id": str(payload.get("alertId") or "").strip(),
        "state": str(payload.get("state") or "").strip(),
        "time": payload.get("time"),
        "raw": payload,
    }

    cache_key = str(payload.get("alertId") or payload.get("id") or "").strip()
    if not cache_key:
        raise HTTPException(status_code=400, detail="Webhook payload is missing alertId")
    webhook_findings = dict(tenant_state.get("webhook_findings") or {})
    webhook_findings[cache_key] = finding_payload
    tenant_state["webhook_findings"] = webhook_findings
    tenant_state["findings"] = _merge_findings(tenant_state.get("findings"), webhook_findings)
    _set_hub_central_status(tenant_id, tenant_state)

    await ws_broadcast(
        {
            "type": "aruba_update",
            "tenant_id": tenant_id,
            "findings": tenant_state.get("findings", []),
            "status": tenant_state.get("status", {}),
            "wireless_clients": tenant_state.get("wireless_clients", {}),
            "hardware_alerts": tenant_state.get("hardware_alerts", []),
            "client_count_status": tenant_state.get("client_count_status", {}),
            "central_sites_config": tenant_state.get("central_sites_config", {}),
            "token_state": tenant_state.get("token_state", {"state": "connected", "detail": ""}),
            "webhook": True,
        }
    )
    logger.info("Received Central webhook for tenant %s alert %s", tenant_id, cache_key)
    return {"received": True}
