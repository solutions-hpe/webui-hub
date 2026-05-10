"""Aruba Central integration helpers for tenant-aware polling and discovery.

``ArubaClient`` wraps the token and request logic needed by Hub background
workers. It supports the legacy/classic Aruba Central token flow, the newer
``new_central`` client-credentials flow, alert and insight polling across the
supported monitoring endpoints, and MSP customer discovery for converting Aruba
Central tenants into Hub tenants.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ArubaFinding:
    site_name: str
    check_name: str
    status: str  # "red" | "yellow" | "green"
    source: str  # "alert" | "insight"
    raw: dict[str, Any] = field(default_factory=dict)


class ArubaClient:
    """Aruba Central API client. One instance per tenant config."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = dict(config)
        self.cluster_url = (self.config.get("cluster_url") or "").rstrip("/")
        self.api_version = (self.config.get("api_version") or "classic").strip()
        self._config_hash = hashlib.md5(
            json.dumps(self.config, sort_keys=True, default=str).encode()
        ).hexdigest()[:8]
        self._token_cache: dict[str, dict[str, Any]] = {self._config_hash: {}}

    def is_configured(self) -> bool:
        """Return ``True`` when the minimum Aruba endpoint configuration is present."""
        return bool(self.cluster_url)

    def _token_state(self) -> dict[str, Any]:
        return self._token_cache.setdefault(self._config_hash, {})

    async def _ensure_token(self, client: httpx.AsyncClient) -> str:
        now = time.time()
        token_state = self._token_state()
        if token_state.get("access_token") and token_state.get("expires_at", 0) > now + 60:
            return token_state["access_token"]

        if self.api_version == "new_central":
            resp = await client.post(
                f"{self.cluster_url}/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.get("client_id", ""),
                    "client_secret": self.config.get("client_secret", ""),
                },
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
            token_state.clear()
            token_state.update(
                {
                    "access_token": payload["access_token"],
                    "expires_at": now + int(payload.get("expires_in", 3600)),
                }
            )
            return token_state["access_token"]

        access_token = self.config.get("access_token")
        refresh_token = self.config.get("refresh_token")

        if access_token and not refresh_token:
            token_state.clear()
            token_state.update({"access_token": access_token, "expires_at": now + 3600})
            return access_token

        if not refresh_token:
            raise ValueError("Aruba Central credentials incomplete — need access_token or refresh_token")

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.get("client_id", ""),
            "client_secret": self.config.get("client_secret", ""),
        }
        if self.config.get("customer_id"):
            data["customer_id"] = self.config["customer_id"]

        resp = await client.post(f"{self.cluster_url}/oauth2/token", data=data, timeout=15)
        resp.raise_for_status()
        payload = resp.json()
        token_state.clear()
        token_state.update(
            {
                "access_token": payload["access_token"],
                "refresh_token": payload.get("refresh_token", refresh_token),
                "expires_at": now + int(payload.get("expires_in", 3600)),
            }
        )
        return token_state["access_token"]

    def _headers(self, token: str) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {token}"}
        if self.config.get("customer_id"):
            headers["X-Customer-ID"] = str(self.config["customer_id"])
        return headers

    async def _get(self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None) -> Any:
        token = await self._ensure_token(client)
        resp = await client.get(
            f"{self.cluster_url}{path}",
            headers=self._headers(token),
            params=params or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _finding_status(value: Any) -> str:
        sev = str(value or "").strip().lower()
        if sev in {"critical", "major", "red", "open", "error"}:
            return "red"
        if sev in {"clear", "closed", "normal", "ok", "green", "resolved"}:
            return "green"
        return "yellow"

    async def poll_alerts_and_insights(self, site_filter: Optional[str] = None) -> list[ArubaFinding]:
        """Collect Aruba alerts and insights across the supported API variants for a tenant."""
        if not self.is_configured():
            return []

        findings: list[ArubaFinding] = []
        async with httpx.AsyncClient(timeout=30) as client:
            if self.api_version == "new_central":
                try:
                    data = await self._get(client, "/network-monitoring/v1alpha1/sites-health")
                    for item in data.get("items") or []:
                        site = (item.get("siteName") or item.get("site_name") or "unknown").strip() or "unknown"
                        if site_filter and site.lower() != site_filter.lower():
                            continue
                        findings.append(
                            ArubaFinding(
                                site_name=site,
                                check_name="SITE_HEALTH",
                                status="green" if int(item.get("healthScore", item.get("health_score", 100))) >= 80 else "yellow",
                                source="alert",
                                raw=item,
                            )
                        )
                except Exception as exc:
                    logger.warning("Aruba sites-health fetch failed [%s]: %s", self._config_hash, exc)
                return findings

            params: dict[str, Any] = {"limit": 1000}
            if site_filter:
                params["site"] = site_filter

            try:
                alerts_payload = None
                for alerts_path in ("/monitoring/v1/alerts", "/monitoring/v2/alerts", "/aiops/v2/alerts"):
                    try:
                        alerts_payload = await self._get(client, alerts_path, params=params)
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                for alert in (alerts_payload or {}).get("alerts") or (alerts_payload or {}).get("items") or []:
                    site = (alert.get("site_name") or alert.get("site") or alert.get("group") or "unknown").strip() or "unknown"
                    name = (
                        alert.get("name")
                        or alert.get("alert_name")
                        or alert.get("rule")
                        or alert.get("alert_type")
                        or "alert"
                    )
                    status = self._finding_status(alert.get("severity") or alert.get("status"))
                    findings.append(ArubaFinding(site_name=site, check_name=str(name), status=status, source="alert", raw=alert))
            except Exception as exc:
                logger.warning("Aruba alerts fetch failed [%s]: %s", self._config_hash, exc)

            insight_params = dict(params)
            if site_filter:
                insight_params["site_name"] = site_filter
                insight_params.pop("site", None)
            try:
                insights_payload = None
                for insights_path in ("/aiops/v1/insights", "/aiops/v2/insights"):
                    try:
                        insights_payload = await self._get(client, insights_path, params=insight_params)
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                for insight in (insights_payload or {}).get("insights") or (insights_payload or {}).get("items") or []:
                    site = (insight.get("site_name") or insight.get("site") or insight.get("group") or "unknown").strip() or "unknown"
                    name = (
                        insight.get("name")
                        or insight.get("insight_name")
                        or insight.get("rule")
                        or insight.get("category")
                        or "insight"
                    )
                    status = self._finding_status(insight.get("severity") or insight.get("status"))
                    findings.append(ArubaFinding(site_name=site, check_name=str(name), status=status, source="insight", raw=insight))
            except Exception as exc:
                logger.warning("Aruba insights fetch failed [%s]: %s", self._config_hash, exc)

        return findings

    async def discover_tenants(self) -> list[dict[str, Any]]:
        """Discover Aruba MSP customer tenants and normalize them to ``{cid, name}`` pairs."""
        if not self.is_configured():
            return []

        endpoints = (
            "/msptopo/v1/customer_list",
            "/msp_api/v1/customer_list",
            "/platform/msp/customer_list",
        )
        async with httpx.AsyncClient(timeout=30) as client:
            for path in endpoints:
                try:
                    data = await self._get(client, path)
                    customers = data.get("customers") or data.get("items") or data.get("data") or []
                    results = [
                        {
                            "cid": str(c.get("customer_id") or c.get("cid") or c.get("id") or ""),
                            "name": c.get("customer_name") or c.get("name") or c.get("cid") or c.get("id") or "",
                        }
                        for c in customers
                        if c.get("customer_id") or c.get("cid") or c.get("id")
                    ]
                    if results:
                        return results
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        continue
                    logger.warning("Aruba MSP tenant discovery failed [%s]: %s", self._config_hash, exc)
                    return []
                except Exception as exc:
                    logger.warning("Aruba MSP tenant discovery failed [%s]: %s", self._config_hash, exc)
                    return []
        return []
