"""Aruba Central integration helpers for tenant-aware polling and discovery.

``ArubaClient`` wraps the token and request logic needed by Hub background
workers. It supports the legacy/classic Aruba Central token flow, the newer
``new_central`` client-credentials flow, alert and insight polling across the
supported monitoring endpoints, and MSP customer discovery for converting Aruba
Central tenants into Hub tenants.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_NEW_CENTRAL_TOKEN_URL = "https://sso.common.cloud.hpe.com/as/token.oauth2"
_GLP_TOKEN_URL_TEMPLATE = "https://global.api.greenlake.hpe.com/authorization/v2/oauth2/{workspace_id}/token"
_KNOWN_CENTRAL_GATEWAY_SUFFIXES = (".api.central.arubanetworks.com", ".api.central.arubanetworks.com.cn")

DEFAULT_NEW_CENTRAL_MONITORED_CHECKS: tuple[dict[str, str], ...] = (
    {"type": "alert", "id": "SITE_HEALTH", "name": "Site Health Score (0–100)"},
    {"type": "alert", "id": "AP_DOWN", "name": "APs Down / Offline"},
    {"type": "alert", "id": "SWITCH_DOWN", "name": "Switches Down / Offline"},
    {"type": "alert", "id": "GATEWAY_DOWN", "name": "Gateways Down / Offline"},
    {"type": "alert", "id": "CLIENT_COUNT", "name": "Connected Client Count"},
)
DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS: tuple[dict[str, str], ...] = (
    {"id": "AP_DOWN", "name": "APs Down / Offline", "device_type": "ap"},
    {"id": "SWITCH_DOWN", "name": "Switches Down / Offline", "device_type": "switch"},
    {"id": "GATEWAY_DOWN", "name": "Gateways Down / Offline", "device_type": "gateway"},
)
KNOWN_CLASSIC_ALERT_TYPES: dict[str, str] = {
    "AP_DOWN": "AP Down",
    "AP_UP": "AP Up",
    "ACCESS_POINT_DOWN": "Access Point Down",
    "CLIENT_ASSOCIATION_FAILURE": "Client Association Failure",
    "CLIENT_DHCP_FAILURE": "Client DHCP Failure",
    "CLIENT_DISCONNECTED": "Client Disconnected",
    "DHCP_POOL_EXHAUSTED": "DHCP Pool Exhausted",
    "IDS_AP_SPOOFED": "IDS AP Spoofed",
    "PORTAL_DOWN": "Portal Down",
    "RADIO_INTERFERENCE": "Radio Interference",
    "ROGUE_AP_DETECTED": "Rogue AP Detected",
    "SWITCH_DOWN": "Switch Down",
    "SWITCH_PORT_DOWN": "Switch Port Down",
    "TUNNEL_DOWN": "Tunnel Down",
    "UPLINK_FAILURE": "Uplink Failure",
    "VPN_TUNNEL_DOWN": "VPN Tunnel Down",
    "WIRELESS_CLIENT_ROAM": "Wireless Client Roam",
    "WIRELESS_INTERFERENCE": "Wireless Interference",
}
KNOWN_CLASSIC_INSIGHT_CATEGORIES: dict[str, str] = {
    "CONNECTIVITY": "Connectivity",
    "PERFORMANCE": "Performance",
    "RELIABILITY": "Reliability",
    "SECURITY": "Security",
}


def validate_cluster_url(cluster_url: str) -> str:
    normalized = str(cluster_url or "").strip().rstrip("/")
    if not normalized:
        raise ValueError("cluster_url is required")

    parsed = urlparse(normalized)
    if parsed.scheme != "https":
        raise ValueError("cluster_url must use https")
    if not parsed.hostname:
        raise ValueError("cluster_url must include a hostname")

    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"cluster_url hostname could not be resolved: {exc}") from exc

    for _, _, _, _, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError(
                f"cluster_url resolves to disallowed address {ip}"
            )

    hostname = parsed.hostname.casefold()
    if not hostname.endswith(_KNOWN_CENTRAL_GATEWAY_SUFFIXES):
        logger.warning(
            "Aruba cluster_url host %s does not match known Central API gateway patterns",
            parsed.hostname,
        )

    return normalized


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

    def _new_central_token_url(self) -> str:
        workspace_id = str(self.config.get("workspace_id") or "").strip()
        if workspace_id:
            return _GLP_TOKEN_URL_TEMPLATE.format(workspace_id=workspace_id)
        return _NEW_CENTRAL_TOKEN_URL

    async def _ensure_token(self, client: httpx.AsyncClient) -> str:
        now = time.time()
        token_state = self._token_state()
        if token_state.get("access_token") and token_state.get("expires_at", 0) > now + 60:
            return token_state["access_token"]

        if self.api_version == "new_central":
            # If a static access token is provided, use it directly (no OAuth exchange).
            static_token = str(self.config.get("access_token") or "").strip()
            if static_token:
                token_state.clear()
                token_state.update({"access_token": static_token, "expires_at": now + 7200})
                return static_token

            workspace_id = str(self.config.get("workspace_id") or "").strip()
            resp = await client.post(
                self._new_central_token_url(),
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.get("client_id", ""),
                    "client_secret": self.config.get("client_secret", ""),
                },
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
            if "access_token" not in payload:
                raise ValueError(f"Token endpoint returned no access_token. Response: {json.dumps(payload)[:300]}")
            token_state.clear()
            token_state.update(
                {
                    "access_token": payload["access_token"],
                    "expires_at": now + int(payload.get("expires_in", 900 if workspace_id else 7200)),
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
                        site = (item.get("name") or item.get("siteName") or item.get("site_name") or "unknown").strip() or "unknown"
                        if site_filter and site.lower() != site_filter.lower():
                            continue
                        good_pct = next(
                            (g.get("value", 0) for g in (item.get("health") or {}).get("groups", []) if g.get("name") == "Good"),
                            item.get("healthScore", item.get("health_score", 100)),
                        )
                        findings.append(
                            ArubaFinding(
                                site_name=site,
                                check_name="SITE_HEALTH",
                                status="green" if int(good_pct or 0) >= 80 else "yellow",
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

    async def poll_site_data(
        self,
        site: str,
        hw_check_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Collect per-site Aruba Central health, counts, and hardware device names."""
        if not self.is_configured():
            return {
                "site_health": None,
                "wireless_clients": 0,
                "client_count": 0,
                "alert_type_counts": {},
                "insight_cat_counts": {},
                "hw_devices": {},
            }

        hw_check_ids = {str(check_id).strip() for check_id in (hw_check_ids or set()) if str(check_id).strip()}
        site_health: int | None = None
        wireless_clients = 0
        alert_type_counts: dict[str, int] = {}
        insight_cat_counts: dict[str, int] = {}
        hw_devices: dict[str, dict[str, int]] = {}

        async with httpx.AsyncClient(timeout=30) as client:
            if self.api_version == "new_central":
                site_id: str | None = None
                try:
                    data = await self._get(client, "/network-monitoring/v1alpha1/sites-health")
                    for item in data.get("items") or []:
                        site_name = (item.get("name") or item.get("siteName") or item.get("site_name") or "").strip()
                        if site_name.lower() != site.lower():
                            continue
                        site_id = item.get("id") or item.get("siteId") or item.get("site_id")
                        good_pct = next(
                            (g.get("value", 0) for g in (item.get("health") or {}).get("groups", []) if g.get("name") == "Good"),
                            item.get("healthScore", item.get("health_score", 0)),
                        )
                        site_health = int(good_pct or 0)
                        wireless_clients = int((item.get("clients") or {}).get("count") or item.get("clientCount") or item.get("client_count") or 0)
                        break
                except Exception as exc:
                    logger.warning("Aruba sites-health fetch failed [%s:%s]: %s", self._config_hash, site, exc)

                try:
                    params: dict[str, Any] = {"limit": 500}
                    if site_id:
                        params["filter"] = f"siteId eq '{site_id}'"
                        logger.debug(
                            "Aruba New Central devices query uses filter=%s; verify syntax against the API reference if results look incomplete",
                            params["filter"],
                        )
                    data = await self._get(client, "/network-monitoring/v1alpha1/devices", params=params)
                    for device in data.get("items") or []:
                        if site_id and str(device.get("siteId") or device.get("site_id") or device.get("id") or "") != str(site_id):
                            continue
                        device_type = str(device.get("deviceType") or "").upper()
                        status = str(device.get("status") or "").upper()
                        if status in {"UP", "ONLINE"}:
                            continue
                        if device_type == "ACCESS_POINT":
                            alert_id = "AP_DOWN"
                        elif device_type == "SWITCH":
                            alert_id = "SWITCH_DOWN"
                        elif device_type == "GATEWAY":
                            alert_id = "GATEWAY_DOWN"
                        else:
                            continue
                        alert_type_counts[alert_id] = alert_type_counts.get(alert_id, 0) + 1
                        if not hw_check_ids or alert_id in hw_check_ids:
                            device_name = (
                                device.get("deviceName")
                                or device.get("name")
                                or device.get("id")
                                or device.get("serialNumber")
                                or device.get("serial")
                                or ""
                            ).strip()
                            if device_name:
                                hw_devices.setdefault(alert_id, {})[device_name] = hw_devices.setdefault(alert_id, {}).get(device_name, 0) + 1
                except Exception as exc:
                    logger.warning("Aruba devices fetch failed [%s:%s]: %s", self._config_hash, site, exc)

                try:
                    params = {"site-id": site_id} if site_id else None
                    if params:
                        logger.debug(
                            "Aruba New Central clients query uses params=%s; verify syntax against the API reference if results look incomplete",
                            params,
                        )
                    data = await self._get(client, "/network-monitoring/v1alpha1/clients", params=params)
                    wireless_clients = int(data.get("count") or wireless_clients or 0)
                except Exception as exc:
                    logger.warning("Aruba clients fetch failed [%s:%s]: %s", self._config_hash, site, exc)

                return {
                    "site_health": site_health,
                    "wireless_clients": wireless_clients,
                    "client_count": wireless_clients,
                    "alert_type_counts": alert_type_counts,
                    "insight_cat_counts": insight_cat_counts,
                    "hw_devices": hw_devices,
                }

            params: dict[str, Any] = {"site": site, "limit": 1000}
            try:
                alerts_payload = None
                for alerts_path in ("/monitoring/v1/alerts", "/monitoring/v2/alerts"):
                    try:
                        alerts_payload = await self._get(client, alerts_path, params=params)
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                for alert in (alerts_payload or {}).get("alerts") or (alerts_payload or {}).get("items") or []:
                    alert_type = str(alert.get("alert_type") or alert.get("type") or "").strip()
                    if not alert_type:
                        continue
                    alert_type_counts[alert_type] = alert_type_counts.get(alert_type, 0) + 1
                    if hw_check_ids and alert_type in hw_check_ids:
                        device_name = (
                            alert.get("device_name")
                            or alert.get("hostname")
                            or alert.get("name")
                            or ""
                        ).strip()
                        if device_name:
                            hw_devices.setdefault(alert_type, {})[device_name] = hw_devices.setdefault(alert_type, {}).get(device_name, 0) + 1
            except Exception as exc:
                logger.warning("Aruba alerts fetch failed [%s:%s]: %s", self._config_hash, site, exc)

            insight_params = {"site_name": site, "limit": 1000}
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
                    category = str(insight.get("category") or insight.get("type") or "").strip()
                    if category:
                        insight_cat_counts[category] = insight_cat_counts.get(category, 0) + 1
            except Exception as exc:
                logger.warning("Aruba insights fetch failed [%s:%s]: %s", self._config_hash, site, exc)

            fetched_wireless = False
            for clients_path in ("/monitoring/v2/clients/wireless", "/monitoring/v1/clients/wireless"):
                for site_param in ("site", "site_name"):
                    try:
                        payload = await self._get(client, clients_path, params={site_param: site, "limit": 1})
                        wireless_clients = int(payload.get("total") or payload.get("count") or 0)
                        fetched_wireless = True
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                    except Exception as exc:
                        logger.warning("Aruba wireless clients fetch failed [%s:%s]: %s", self._config_hash, site, exc)
                        break
                if fetched_wireless:
                    break

        return {
            "site_health": site_health,
            "wireless_clients": wireless_clients,
            "client_count": wireless_clients,
            "alert_type_counts": alert_type_counts,
            "insight_cat_counts": insight_cat_counts,
            "hw_devices": hw_devices,
        }

    async def list_sites(self) -> list[dict[str, Any]]:
        """Return normalized Aruba Central sites for hub auto-discovery."""
        if not self.is_configured():
            return []

        sites: dict[str, dict[str, Any]] = {}
        async with httpx.AsyncClient(timeout=30) as client:
            if self.api_version == "new_central":
                data = await self._get(client, "/network-monitoring/v1alpha1/sites-health")
                for item in data.get("items") or []:
                    site_name = (item.get("name") or item.get("siteName") or item.get("site_name") or "").strip()
                    if not site_name:
                        continue
                    key = site_name.casefold()
                    sites[key] = {
                        "name": site_name,
                        "site_id": item.get("id") or item.get("siteId") or item.get("site_id") or "",
                        "health_score": next(
                            (g.get("value", 0) for g in (item.get("health") or {}).get("groups", []) if g.get("name") == "Good"),
                            item.get("healthScore", item.get("health_score")),
                        ),
                        "wireless_clients": (item.get("clients") or {}).get("count") or item.get("clientCount") or item.get("client_count"),
                    }
                return sorted(sites.values(), key=lambda item: item["name"].casefold())

        try:
            findings = await self.poll_alerts_and_insights()
        except Exception as exc:
            logger.warning("Aruba classic site discovery failed [%s]: %s", self._config_hash, exc)
            findings = []
        for finding in findings:
            site_name = str(finding.site_name or "").strip()
            if not site_name:
                continue
            sites.setdefault(site_name.casefold(), {"name": site_name})
        return sorted(sites.values(), key=lambda item: item["name"].casefold())

    async def list_clients(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return normalized wireless clients from Central API."""
        if not self.is_configured():
            return []
        async with httpx.AsyncClient(timeout=30) as client:
            if self.api_version == "new_central":
                try:
                    data = await self._get(client, "/network-monitoring/v1alpha1/clients", params={"limit": limit})
                    return [
                        {
                            "mac": item.get("macAddress") or item.get("mac") or "—",
                            "ip": item.get("ipv4") or item.get("ip") or "—",
                            "hostname": item.get("name") or item.get("hostname") or "—",
                            "site": item.get("siteName") or item.get("site_name") or "—",
                            "ap": item.get("associatedDevice") or item.get("ap_name") or "—",
                            "ssid": item.get("ssid") or "—",
                            "status": item.get("status") or "—",
                            "os": item.get("os_type") or "—",
                            "vlan": str(item.get("vlan") or "—"),
                        }
                        for item in (data.get("items") or [])
                    ]
                except Exception as exc:
                    logger.warning("list_clients new_central failed [%s]: %s", self._config_hash, exc)
                    return []
            for path in ("/monitoring/v2/clients/wireless", "/monitoring/v1/clients/wireless"):
                try:
                    data = await self._get(client, path, params={"limit": limit})
                    return [
                        {
                            "mac": item.get("macaddr") or item.get("mac") or "—",
                            "ip": item.get("ip_address") or item.get("ip") or "—",
                            "hostname": item.get("name") or item.get("hostname") or "—",
                            "site": item.get("site") or item.get("site_name") or "—",
                            "ap": item.get("associated_device_name") or item.get("ap_name") or "—",
                            "ssid": item.get("ssid") or "—",
                            "status": item.get("status") or "connected",
                            "os": item.get("os_type") or "—",
                            "vlan": str(item.get("vlan_id") or item.get("vlan") or "—"),
                        }
                        for item in (data.get("clients") or data.get("items") or [])
                    ]
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        continue
                    logger.warning("list_clients classic failed [%s] %s: %s", self._config_hash, path, exc)
                    return []
                except Exception as exc:
                    logger.warning("list_clients classic failed [%s] %s: %s", self._config_hash, path, exc)
                    return []
            return []

    async def browse_all(self) -> dict[str, Any]:
        """Fetch all Central sites, alerts, insights, and clients for the browse view."""
        import asyncio

        sites, findings, clients = await asyncio.gather(
            self.list_sites(),
            self.poll_alerts_and_insights(),
            self.list_clients(),
            return_exceptions=True,
        )
        if isinstance(sites, Exception):
            sites = []
        if isinstance(findings, Exception):
            findings = []
        if isinstance(clients, Exception):
            clients = []
        alerts = [
            {"name": f.check_name, "site": f.site_name, "severity": f.status, "detail": "", "ts": None}
            for f in findings
            if isinstance(f, ArubaFinding) and f.source == "alert"
        ]
        insights = [
            {"name": f.check_name, "site": f.site_name, "severity": f.status, "category": "", "ts": None}
            for f in findings
            if isinstance(f, ArubaFinding) and f.source == "insight"
        ]
        return {"sites": sites, "alerts": alerts, "insights": insights, "clients": clients}

    async def register_webhook(self, name: str, endpoint_url: str, api_key: str) -> dict[str, Any]:
        """Register a webhook with Central. Returns the created webhook object."""
        async with httpx.AsyncClient(timeout=15) as client:
            token = await self._ensure_token(client)
            resp = await client.post(
                f"{self.cluster_url}/network-services/v1/webhooks",
                headers=self._headers(token),
                json={
                    "name": name,
                    "endpointURL": endpoint_url,
                    "authMechanism": {"type": "API_KEY", "apiKey": api_key},
                },
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()

    async def list_webhooks(self) -> list[dict[str, Any]]:
        """List all registered webhooks."""
        async with httpx.AsyncClient(timeout=15) as client:
            data = await self._get(client, "/network-services/v1/webhooks")
            if isinstance(data, dict):
                items = data.get("items")
                return items if isinstance(items, list) else []
            return data if isinstance(data, list) else []

    async def delete_webhook(self, webhook_id: str) -> None:
        """Delete a webhook by ID."""
        async with httpx.AsyncClient(timeout=15) as client:
            token = await self._ensure_token(client)
            resp = await client.delete(
                f"{self.cluster_url}/network-services/v1/webhooks/{webhook_id}",
                headers=self._headers(token),
                timeout=15,
            )
            if resp.status_code != 404:
                resp.raise_for_status()

    async def available_checks(self) -> dict[str, Any]:
        """Return Aruba Central alert, insight, and hardware catalogs for the UI."""
        if not self.is_configured():
            return {"alerts": [], "insights": [], "hardware": [], "warning": "Central not configured."}

        if self.api_version == "new_central":
            return {
                "alerts": [dict(item) for item in DEFAULT_NEW_CENTRAL_MONITORED_CHECKS],
                "insights": [],
                "hardware": [dict(item) for item in DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS],
                "warning": None,
            }

        alert_types: dict[str, str] = {}
        insight_categories: dict[str, str] = {}
        warnings: list[str] = []
        thirty_days_ago = int(time.time()) - 30 * 86400

        async with httpx.AsyncClient(timeout=30) as client:
            for alerts_path in ("/monitoring/v1/alerts", "/monitoring/v2/alerts", "/aiops/v2/alerts"):
                try:
                    payload = await self._get(client, alerts_path, params={"limit": 1000, "from_timestamp": thirty_days_ago})
                    for alert in payload.get("alerts") or payload.get("items") or []:
                        alert_id = str(alert.get("alert_type") or alert.get("type") or "").strip()
                        if not alert_id:
                            continue
                        alert_types[alert_id] = str(
                            alert.get("alert_type_name")
                            or alert.get("name")
                            or alert_id.replace("_", " ").title()
                        )
                    if alert_types:
                        break
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        continue
                    warnings.append(f"Alerts endpoint returned HTTP {exc.response.status_code}.")
                    break
                except Exception as exc:
                    warnings.append(f"Network error fetching alerts: {exc}")
                    break

            for insights_path in ("/aiops/v1/insights", "/aiops/v2/insights"):
                try:
                    payload = await self._get(client, insights_path, params={"limit": 1000, "from_timestamp": thirty_days_ago})
                    for insight in payload.get("insights") or payload.get("items") or []:
                        category = str(insight.get("category") or insight.get("type") or "").strip()
                        if not category:
                            continue
                        insight_categories[category] = str(
                            insight.get("category_name")
                            or insight.get("name")
                            or category.replace("_", " ").title()
                        )
                    if insight_categories:
                        break
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        continue
                    warnings.append(f"Insights endpoint returned HTTP {exc.response.status_code}.")
                    break
                except Exception as exc:
                    warnings.append(f"Network error fetching insights: {exc}")
                    break

        using_fallback = False
        if not alert_types:
            alert_types = dict(KNOWN_CLASSIC_ALERT_TYPES)
            using_fallback = True
        if not insight_categories:
            insight_categories = dict(KNOWN_CLASSIC_INSIGHT_CATEGORIES)
            using_fallback = True
        if using_fallback:
            warnings.append("No live checks returned by Central — showing standard Aruba Central check types.")

        hardware_catalog = [
            dict(item)
            for item in DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS
            if item.get("id") in alert_types or item.get("id") in {"AP_DOWN", "SWITCH_DOWN", "GATEWAY_DOWN"}
        ]
        return {
            "alerts": [{"id": key, "name": value} for key, value in sorted(alert_types.items())],
            "insights": [{"id": key, "name": value} for key, value in sorted(insight_categories.items())],
            "hardware": hardware_catalog,
            "warning": "; ".join(dict.fromkeys(warnings)) if warnings else None,
        }

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
