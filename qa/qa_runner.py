#!/usr/bin/env python3
"""Client-Sim QA Runner
========================
Automated end-to-end QA process for the hub-spoke-client pipeline.

A tenant-scoped QA API key is required.  Only a superadmin can generate one:

    POST /api/superadmin/qa-api-keys
    {"tenant_id": "<id>", "description": "CI key"}

Usage
-----
    python3 qa/qa_runner.py --url https://localhost:8443 --qa-key <key>

    # Or use environment variables:
    CS_HUB_URL=https://... CS_QA_API_KEY=cs-qa-... python3 qa/qa_runner.py

    # Skip TLS verification (self-signed certs):
    python3 qa/qa_runner.py --no-verify --qa-key <key>

    # JSON output (for CI / Copilot parsing):
    python3 qa/qa_runner.py --json --qa-key <key>

    # Only run specific phases:
    python3 qa/qa_runner.py --phases provisioning,health --qa-key <key>

Exit codes
----------
    0  All tests passed
    1  One or more tests failed
    2  Fatal error (cannot reach hub / key invalid)
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import httpx
except ImportError:
    print("ERROR: httpx is required.  Run: pip install httpx", file=sys.stderr)
    sys.exit(2)

# ── Terminal colours (disabled when --json or not a tty) ─────────────────────
_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

GREEN  = lambda t: _c("32", t)
RED    = lambda t: _c("31", t)
YELLOW = lambda t: _c("33", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)


# ── Result tracking ───────────────────────────────────────────────────────────

@dataclass
class TestResult:
    name: str
    phase: str
    passed: bool
    detail: str = ""
    skipped: bool = False
    warning: bool = False
    raw_data: dict | None = None  # raw API payload captured at failure/warn time for diagnosis


@dataclass
class QARunner:
    base_url: str
    qa_key: str          # raw QA API key — exchanged for a JWT at startup
    tenant_id: str = ""  # populated from the token exchange response
    verify_ssl: bool = True
    timeout: float = 15.0
    results: list[TestResult] = field(default_factory=list)
    token: str = ""
    dump_on_fail: bool = False  # print raw_data under each FAIL/WARN in the text report
    _client: httpx.Client | None = None

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                verify=self.verify_ssl,
                timeout=self.timeout,
                follow_redirects=True,
            )
        return self._client

    def get(self, path: str, **kw: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        return self._http().get(path, headers=headers, **kw)

    def post(self, path: str, json: Any = None, **kw: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        return self._http().post(path, json=json, headers=headers, **kw)

    def patch(self, path: str, json: Any = None, **kw: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        return self._http().patch(path, json=json, headers=headers, **kw)

    def delete(self, path: str, **kw: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        return self._http().delete(path, headers=headers, **kw)

    # ── Result helpers ────────────────────────────────────────────────────────

    def _ok(self, name: str, phase: str, detail: str = "") -> TestResult:
        r = TestResult(name=name, phase=phase, passed=True, detail=detail)
        self.results.append(r)
        return r

    def _fail(self, name: str, phase: str, detail: str = "", raw_data: dict | None = None) -> TestResult:
        r = TestResult(name=name, phase=phase, passed=False, detail=detail, raw_data=raw_data)
        self.results.append(r)
        return r

    def _skip(self, name: str, phase: str, reason: str = "") -> TestResult:
        r = TestResult(name=name, phase=phase, passed=True, skipped=True, detail=reason)
        self.results.append(r)
        return r

    def _warn(self, name: str, phase: str, detail: str = "", raw_data: dict | None = None) -> TestResult:
        r = TestResult(name=name, phase=phase, passed=True, warning=True, detail=detail, raw_data=raw_data)
        self.results.append(r)
        return r

    @staticmethod
    def _spoke_diag(h: dict) -> dict:
        """Build a compact diagnostic snapshot from a proxmox aggregate host entry.

        Attached as raw_data to per-spoke FAIL/WARN results so Copilot can identify
        the root cause from the QA output alone.
        """
        vms = h.get("proxmox_vms") or []
        return {
            "spoke_id":              h.get("spoke_id"),
            "spoke_name":            h.get("spoke_name"),
            "spoke_online":          h.get("spoke_online"),
            "proxmox":               h.get("proxmox", {}),          # connected, last_seen, agent_id
            "hub_loop_lag_ms":       h.get("hub_loop_lag_ms"),
            "telemetry_build_ms":    h.get("telemetry_build_ms"),
            "ws_reconnect_count":    h.get("ws_reconnect_count"),
            "ws_last_reconnect_at":  h.get("ws_last_reconnect_at"),
            "ws_last_error":         h.get("ws_last_error"),
            "sim_conf_read_error":   h.get("sim_conf_read_error"),
            "vm_count":              h.get("vm_count", 0),
            "proxmox_vms_summary":   [
                {k: v.get(k) for k in ("vmid", "name", "status", "prov_status", "cpu", "mem", "maxmem")}
                for v in vms[:20]  # cap at 20 VMs to keep output manageable
            ],
        }

    def _check(
        self,
        name: str,
        phase: str,
        resp: httpx.Response,
        *,
        expect_status: int = 200,
        assert_keys: list[str] | None = None,
        assert_fn: Any = None,
        warn_fn: Any = None,
    ) -> TestResult:
        """Run a single API assertion and record result."""
        try:
            if resp.status_code != expect_status:
                return self._fail(
                    name, phase,
                    f"HTTP {resp.status_code} (expected {expect_status}): {resp.text[:200]}"
                )
            data: Any = resp.json() if resp.content else {}
            if assert_keys:
                missing = [k for k in assert_keys if k not in data]
                if missing:
                    return self._fail(name, phase, f"Missing keys in response: {missing}")
            if assert_fn:
                result = assert_fn(data)
                if isinstance(result, str):  # returned an error string
                    return self._fail(name, phase, result)
            if warn_fn:
                w = warn_fn(data)
                if isinstance(w, str):
                    return self._warn(name, phase, w)
            return self._ok(name, phase)
        except Exception as exc:  # noqa: BLE001
            return self._fail(name, phase, f"Exception: {exc}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — Authentication
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_auth(self) -> None:
        _section("Phase 1 — Authentication")

        # 1.1 Exchange QA API key for a tenant-scoped JWT
        r = self._http().post("/api/qa/auth", json={"qa_api_key": self.qa_key})
        if r.status_code != 200:
            self._fail("QA key exchange", "auth", f"HTTP {r.status_code}: {r.text[:200]}")
            raise SystemExit(2)
        data = r.json()
        token = data.get("access_token", "")
        if not token:
            self._fail("QA key exchange — token present", "auth", f"No token in response: {data}")
            raise SystemExit(2)
        self.token = token
        self.tenant_id = data.get("tenant_id", self.tenant_id)
        self._ok("QA key exchange", "auth",
                 f"tenant={self.tenant_id}, expires_in={data.get('expires_in_minutes')}m")

        # 1.2 Auth check — verify the token works
        r = self.get("/api/auth/me")
        self._check("Token valid (/api/auth/me)", "auth", r)

        # 1.3 Unauthenticated request is blocked
        r = self._http().get("/api/aggregate/dashboard")
        if r.status_code in (401, 403):
            self._ok("Unauthenticated request blocked", "auth")
        else:
            self._fail("Unauthenticated request blocked", "auth",
                       f"Expected 401/403, got {r.status_code}")

        # 1.4 Invalid key is rejected
        r = self._http().post("/api/qa/auth", json={"qa_api_key": "invalid-key"})
        if r.status_code == 401:
            self._ok("Invalid QA key rejected", "auth")
        else:
            self._fail("Invalid QA key rejected", "auth", f"Expected 401, got {r.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — Hub & Tenant Health
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_hub_health(self) -> None:
        _section("Phase 2 — Hub & Tenant Health")

        r = self.get("/api/health")
        self._check("Hub /api/health", "hub_health", r)

        r = self.get("/api/init")
        self._check("Hub /api/init", "hub_health", r)

        r = self.get(f"/api/{self.tenant_id}/settings")
        self._check("Tenant settings readable", "hub_health", r)

        r = self.get(f"/api/tenant/{self.tenant_id}/hub-config")
        self._check("Hub config readable", "hub_health", r)

        r = self.get(f"/api/tenant/{self.tenant_id}/onboarding-psk")
        if r.status_code == 200:
            self._ok("Onboarding PSK present", "hub_health")
        else:
            self._warn("Onboarding PSK", "hub_health", f"HTTP {r.status_code} — PSK may not be configured")

        r = self.get("/api/acme/status")
        self._check("ACME status", "hub_health", r)

        r = self.get("/api/superadmin/tenants")
        if r.status_code in (200, 403):
            self._ok("Superadmin tenants endpoint reachable", "hub_health")
        else:
            self._fail("Superadmin tenants endpoint reachable", "hub_health", f"HTTP {r.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3 — Spoke Registration
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_spokes(self) -> None:
        _section("Phase 3 — Spoke Registration & Status")

        r = self.get(f"/api/{self.tenant_id}/spokes")
        res = self._check("List approved spokes", "spokes", r, assert_keys=["spokes"])
        if not res.passed:
            return

        spokes: list[dict] = r.json().get("spokes", [])
        total = len(spokes)
        online = sum(1 for s in spokes if s.get("online") or s.get("status") == "online")

        if total == 0:
            self._warn("Spokes count", "spokes", "No approved spokes — register and approve at least one")
        else:
            self._ok("Spokes count", "spokes", f"{total} approved spoke(s)")

        if total > 0 and online == 0:
            self._fail("Spokes online", "spokes", f"0/{total} spokes online")
        elif total > 0:
            if online < total:
                self._warn("Spokes online", "spokes", f"{online}/{total} spokes online")
            else:
                self._ok("Spokes online", "spokes", f"{online}/{total} spokes online")

        # Check pending spoke queue
        r = self.get(f"/api/tenant/{self.tenant_id}/pending-spokes")
        if r.status_code == 200:
            pending = r.json() if isinstance(r.json(), list) else r.json().get("spokes", [])
            if pending:
                self._warn("Pending spokes", "spokes", f"{len(pending)} spoke(s) awaiting approval")
            else:
                self._ok("No unexpected pending spokes", "spokes")

        # Per-spoke config check
        for spoke in spokes[:3]:  # cap at 3 to keep runtime reasonable
            sid = spoke.get("id") or spoke.get("spoke_id", "")
            if not sid:
                continue
            r = self.get(f"/api/{self.tenant_id}/spokes/{sid}/config")
            self._check(f"Spoke {spoke.get('spoke_name') or sid} config readable", "spokes", r)

        # Aggregate dashboard
        r = self.get("/api/aggregate/dashboard", params={"tenant_id": self.tenant_id})
        self._check("Aggregate dashboard", "spokes", r,
                    assert_keys=["spokes_total", "spokes_online", "client_count"])

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4 — Proxmox Agent
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_proxmox(self) -> None:
        _section("Phase 4 — Proxmox Agent & Telemetry")

        r = self.get("/api/aggregate/proxmox", params={"tenant_id": self.tenant_id})
        res = self._check("Aggregate Proxmox telemetry", "proxmox", r, assert_keys=["hosts"])
        if not res.passed:
            return

        hosts: list[dict] = r.json().get("hosts", [])
        if not hosts:
            self._warn("Proxmox agents", "proxmox", "No hosts in Proxmox telemetry — no spokes with Proxmox agents?")
            return

        connected = sum(1 for h in hosts if h.get("proxmox", {}).get("connected"))
        total = len(hosts)
        if connected == 0:
            self._fail("Proxmox agents connected", "proxmox", f"0/{total} agents connected")
        elif connected < total:
            self._warn("Proxmox agents connected", "proxmox", f"{connected}/{total} agents connected")
        else:
            self._ok("Proxmox agents connected", "proxmox", f"{connected}/{total}")

        # Check VM counts are non-zero on any host that has dongles
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            dongles = h.get("spoke_config", {})
            usb_count = h.get("usb_count", 0)
            vm_count = h.get("vm_count", 0)
            if usb_count > 0 and vm_count == 0:
                self._fail(
                    f"Spoke '{name}' VM count",
                    "proxmox",
                    f"{usb_count} dongle(s) detected but vm_count=0 — VMs may not have been cloned",
                )
            elif usb_count > 0:
                self._ok(f"Spoke '{name}' VM count", "proxmox", f"vms={vm_count}, dongles={usb_count}")

        # Check prov_status is populated on proxmox_vms (validates the usb_state join)
        # prov_status is joined from usb_state by vmid; absence means the join never ran or
        # the proxmox agent hasn't sent usb_state yet.
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            vms: list[dict] = h.get("proxmox_vms", [])
            if not vms:
                continue  # already reported by vm_count check above

            missing_status = [v for v in vms if not v.get("prov_status")]
            provisioning  = [v for v in vms if v.get("prov_status") == "provisioning"]
            tearing_down  = [v for v in vms if v.get("prov_status") == "tearing_down"]
            active        = [v for v in vms if v.get("prov_status") == "active"]

            if len(missing_status) == len(vms):
                # All VMs lack prov_status — join didn't work or usb_state not yet received
                self._fail(
                    f"Spoke '{name}' VM prov_status",
                    "proxmox",
                    f"prov_status missing on all {len(vms)} VM(s) — "
                    "usb_state may not have arrived yet or agent is not sending it",
                )
            elif missing_status:
                self._warn(
                    f"Spoke '{name}' VM prov_status",
                    "proxmox",
                    f"{len(missing_status)}/{len(vms)} VM(s) have no prov_status "
                    f"(vmids: {[v.get('vmid') for v in missing_status]})",
                )
            else:
                self._ok(
                    f"Spoke '{name}' VM prov_status",
                    "proxmox",
                    f"active={len(active)}, provisioning={len(provisioning)}, "
                    f"tearing_down={len(tearing_down)}",
                )

            # Warn on transitional states — normal during reclone/delete but a red flag at rest
            if provisioning:
                self._warn(
                    f"Spoke '{name}' VMs provisioning",
                    "proxmox",
                    f"{len(provisioning)} VM(s) still in 'provisioning' state "
                    f"(vmids: {[v.get('vmid') for v in provisioning]}) — "
                    "expected only during active reclone",
                )
            if tearing_down:
                self._warn(
                    f"Spoke '{name}' VMs tearing_down",
                    "proxmox",
                    f"{len(tearing_down)} VM(s) still in 'tearing_down' state "
                    f"(vmids: {[v.get('vmid') for v in tearing_down]}) — "
                    "expected only during active teardown",
                )

        # ── Agent approval check ──────────────────────────────────────────────
        # After reinstall the Proxmox agent requires manual approval in the hub UI
        # before it will connect. connected=false + last_seen=null = never approved.
        # (This was the root cause of svr-02 missing during the teardown test.)
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            proxmox = h.get("proxmox", {})
            px_connected = proxmox.get("connected", False)
            px_last_seen = proxmox.get("last_seen")
            if not px_connected and not px_last_seen:
                self._warn(
                    f"Spoke '{name}' proxmox agent approval",
                    "proxmox",
                    "connected=false and last_seen=null — agent has never connected. "
                    "If recently reinstalled, approve it in the hub UI via "
                    "POST /{tenant_id}/aggregate/proxmox-approve-agent",
                    raw_data=self._spoke_diag(h),
                )

        # ── Proxmox agent last_seen freshness ─────────────────────────────────
        # collect_telemetry has a 25s timeout on pvesh; when pvesh blocks during
        # delete/clone the agent falls back to a bare ping which does NOT update
        # last_seen. The hub UI then shows the agent as silent even though the WS
        # connection is fine. Threshold mirrors the live monitor alert (120s warn,
        # 300s fail matching the hub heartbeat_monitor offline threshold).
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            proxmox = h.get("proxmox", {})
            px_connected = proxmox.get("connected", False)
            px_last_seen = proxmox.get("last_seen")
            if not px_connected:
                continue  # disconnected already reported above
            if not px_last_seen:
                self._warn(
                    f"Spoke '{name}' proxmox agent last_seen",
                    "proxmox",
                    "connected=true but last_seen is null — agent has not sent full telemetry yet",
                    raw_data=self._spoke_diag(h),
                )
                continue
            try:
                ls = datetime.datetime.fromisoformat(px_last_seen.replace("Z", "+00:00"))
                age_s = int((datetime.datetime.now(datetime.timezone.utc) - ls).total_seconds())
                if age_s > 300:
                    self._fail(
                        f"Spoke '{name}' proxmox agent freshness",
                        "proxmox",
                        f"last_seen {age_s}s ago (>5 min) — agent may be crashed or pvesh "
                        "permanently blocked; spoke WS may still be connected",
                        raw_data=self._spoke_diag(h),
                    )
                elif age_s > 120:
                    self._warn(
                        f"Spoke '{name}' proxmox agent freshness",
                        "proxmox",
                        f"last_seen {age_s}s ago — pvesh likely blocking during active Proxmox "
                        "operation (delete/clone); collect_telemetry times out and agent falls "
                        "back to bare pings which do not update last_seen",
                        raw_data=self._spoke_diag(h),
                    )
                else:
                    self._ok(
                        f"Spoke '{name}' proxmox agent freshness",
                        "proxmox",
                        f"last_seen {age_s}s ago",
                    )
            except Exception:
                self._warn(
                    f"Spoke '{name}' proxmox agent freshness",
                    "proxmox",
                    f"Could not parse last_seen={px_last_seen!r}",
                )

        # ── Event-loop & WS diagnostic telemetry ─────────────────────────────
        # Fields added in spoke commit 2e06d66 / hub commit 9580b96.
        # All three being None on a connected spoke means old code is running
        # without the synchronous-I/O fixes — reinstall is required.
        #
        # Thresholds are based on observed production values:
        #   hub_loop_lag_ms  0–10ms = healthy; >200ms = sluggish; >500ms = blocked
        #   telemetry_build_ms  0ms = healthy (background cache); >100ms = warn; >500ms = blocking
        #   ws_reconnect_count  1 = clean (initial connect only); >1 = drops occurred
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            if not h.get("spoke_online"):
                continue  # offline spoke — telemetry fields meaningless

            hub_lag_ms = h.get("hub_loop_lag_ms")
            build_ms   = h.get("telemetry_build_ms")
            reconnects = h.get("ws_reconnect_count")
            ws_err     = h.get("ws_last_error")
            sc_err     = h.get("sim_conf_read_error")

            # Detect old spoke code — all three diagnostic fields absent
            if hub_lag_ms is None and build_ms is None and reconnects is None:
                self._fail(
                    f"Spoke '{name}' event-loop fix telemetry present",
                    "proxmox",
                    "hub_loop_lag_ms / telemetry_build_ms / ws_reconnect_count all null on an "
                    "online spoke — spoke is running old code without the synchronous I/O fixes "
                    "(pre-commit 2e06d66). Reinstall via install-lxc.sh to resolve.",
                    raw_data=self._spoke_diag(h),
                )
                continue  # individual field checks are meaningless without the fields

            self._ok(f"Spoke '{name}' event-loop fix telemetry present", "proxmox")

            # Hub event-loop lag (measured by spoke from telemetry_ack roundtrip).
            # High values mean store.get_tenant() or store.save_spoke() is blocking
            # the hub asyncio event loop — root cause of the all-spokes-offline incident.
            if hub_lag_ms is None:
                self._skip(
                    f"Spoke '{name}' hub event-loop lag",
                    "proxmox",
                    "field not in telemetry (old spoke code on this spoke)",
                )
            elif hub_lag_ms > 500:
                self._fail(
                    f"Spoke '{name}' hub event-loop lag",
                    "proxmox",
                    f"{hub_lag_ms:.0f}ms — hub asyncio loop severely blocked; "
                    "root cause: synchronous disk I/O in _apply_spoke_telemetry "
                    "or store.get_tenant() on the hot WS path",
                    raw_data=self._spoke_diag(h),
                )
            elif hub_lag_ms > 200:
                self._warn(
                    f"Spoke '{name}' hub event-loop lag",
                    "proxmox",
                    f"{hub_lag_ms:.0f}ms (warn ≥200ms, fail ≥500ms)",
                    raw_data=self._spoke_diag(h),
                )
            else:
                self._ok(
                    f"Spoke '{name}' hub event-loop lag",
                    "proxmox",
                    f"{hub_lag_ms:.0f}ms",
                )

            # Spoke telemetry build time.
            # High values mean _build_relay_telemetry_payload is blocking on CIFS
            # (synchronous read_text() on the asyncio event loop).
            # With the background sim_conf refresher this should be ~0ms.
            if build_ms is None:
                self._skip(
                    f"Spoke '{name}' telemetry build time",
                    "proxmox",
                    "field not in telemetry (old spoke code on this spoke)",
                )
            elif build_ms > 500:
                self._fail(
                    f"Spoke '{name}' telemetry build time",
                    "proxmox",
                    f"{build_ms:.0f}ms — CIFS stall or blocking I/O in "
                    "_build_relay_telemetry_payload; root cause: synchronous "
                    "Path.read_text() in async hot path (should be ~0ms with cache fix)",
                    raw_data=self._spoke_diag(h),
                )
            elif build_ms > 100:
                self._warn(
                    f"Spoke '{name}' telemetry build time",
                    "proxmox",
                    f"{build_ms:.0f}ms (warn ≥100ms, fail ≥500ms)",
                    raw_data=self._spoke_diag(h),
                )
            else:
                self._ok(
                    f"Spoke '{name}' telemetry build time",
                    "proxmox",
                    f"{build_ms:.0f}ms",
                )

            # WS reconnect count — should be exactly 1 (initial connect at startup).
            # Values >1 indicate the WS connection dropped and was re-established.
            # Values >5 are concerning and likely correlated with hub event-loop blocks.
            if reconnects is None:
                self._skip(
                    f"Spoke '{name}' WS reconnect count",
                    "proxmox",
                    "field not in telemetry (old spoke code on this spoke)",
                )
            elif reconnects > 5:
                self._fail(
                    f"Spoke '{name}' WS reconnect count",
                    "proxmox",
                    f"reconnects={reconnects} — spoke WS is repeatedly dropping; "
                    "check ws_last_error and hub connectivity",
                    raw_data=self._spoke_diag(h),
                )
            elif reconnects > 1:
                self._warn(
                    f"Spoke '{name}' WS reconnect count",
                    "proxmox",
                    f"reconnects={reconnects} — at least one WS drop since last spoke restart",
                    raw_data=self._spoke_diag(h),
                )
            else:
                self._ok(
                    f"Spoke '{name}' WS reconnect count",
                    "proxmox",
                    f"reconnects={reconnects} (clean)",
                )

            # Last WS error — any non-null value means the WS dropped at some point.
            if ws_err:
                self._warn(
                    f"Spoke '{name}' WS last error",
                    "proxmox",
                    f"{ws_err!r} — a WS connection error was recorded; "
                    "hub may have been unreachable or event-loop timed out a ping",
                    raw_data=self._spoke_diag(h),
                )
            elif reconnects is not None:
                self._ok(f"Spoke '{name}' WS last error", "proxmox", "none")

            # sim_conf CIFS background refresh errors.
            # Non-null means the background refresher caught an exception reading
            # the sim_conf from the Azure Files CIFS mount.
            if sc_err:
                self._warn(
                    f"Spoke '{name}' sim_conf refresh",
                    "proxmox",
                    f"sim_conf_read_error={sc_err!r} — CIFS mount stalled during "
                    "background sim_conf refresh; spoke fell back to last cached value",
                )
            elif build_ms is not None:
                self._ok(f"Spoke '{name}' sim_conf refresh", "proxmox", "no errors")

        # ── VM RAM/CPU data quality (balloon driver detection) ─────────────────
        # Without the VirtIO balloon driver installed in guest VMs, Proxmox (pvesh)
        # cannot see inside the guest and reports mem = maxmem for every running VM
        # (full allocation shown as "used"). The UI now renders this as "1.0 GB (alloc)"
        # to distinguish from real usage data.
        # If ALL running VMs on a spoke have mem ≥ maxmem×0.99, balloon is not active.
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            vms: list[dict] = h.get("proxmox_vms", [])
            running = [v for v in vms if v.get("status") == "running"]
            if not running:
                continue

            def _lt_maxmem(v: dict) -> bool:
                try:
                    return float(v.get("mem", 0)) < float(v.get("maxmem", 1)) * 0.99
                except (TypeError, ValueError):
                    return False

            mem_with_data = [v for v in running if _lt_maxmem(v)]
            all_at_alloc = len(mem_with_data) == 0 and all(
                v.get("mem") and v.get("maxmem") for v in running
            )
            if all_at_alloc:
                self._warn(
                    f"Spoke '{name}' VM RAM stats (balloon driver)",
                    "proxmox",
                    f"All {len(running)} running VM(s) report mem=maxmem — VirtIO balloon "
                    "driver is not active in guest VMs. Proxmox cannot report actual RAM usage; "
                    "UI shows '(alloc)' instead of used/total. Install virtio-balloon in VM guests "
                    "to get real RAM utilisation.",
                )
            elif running:
                self._ok(
                    f"Spoke '{name}' VM RAM stats (balloon driver)",
                    "proxmox",
                    f"{len(mem_with_data)}/{len(running)} running VMs report sub-maxmem RAM usage",
                )

        # ── All-zero CPU detection ─────────────────────────────────────────────
        # cpu=0.0 is legitimate for idle VMs (pvesh measures QEMU process CPU time at the
        # hypervisor level). But if EVERY running VM has exactly 0.0% CPU this is worth
        # flagging in case pvesh is returning stale or zeroed data.
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            vms = h.get("proxmox_vms", [])
            running = [v for v in vms if v.get("status") == "running"]
            if len(running) < 2:
                continue  # too few VMs to be meaningful
            zero_cpu = [v for v in running if v.get("cpu") is not None and float(v.get("cpu", 1)) == 0.0]
            if len(zero_cpu) == len(running):
                self._warn(
                    f"Spoke '{name}' VM CPU stats",
                    "proxmox",
                    f"All {len(running)} running VM(s) report cpu=0.0% — VMs may be genuinely "
                    "idle (normal after reclone before simulation traffic starts) or pvesh may be "
                    "returning stale data. Recheck after simulation traffic begins.",
                )
            else:
                self._ok(
                    f"Spoke '{name}' VM CPU stats",
                    "proxmox",
                    f"Non-zero CPU on {len(running) - len(zero_cpu)}/{len(running)} running VMs",
                )

        # ── proxmox-command endpoint auth check ───────────────────────────────
        # Verifies that the current user can reach the proxmox-command relay endpoint.
        # Uses an intentionally-empty body → hub should return 200 (queued) or 422
        # (validation failure for missing fields) — but NOT 403 (auth/member check).
        # A 403 means either the QA API key holder or the logged-in user is not an
        # explicit tenant member (fixed: superadmin is now allowed through with a log).
        for h in hosts:
            name = h.get("spoke_name", h.get("spoke_id", "?"))
            spoke_id = h.get("spoke_id")
            if not spoke_id:
                continue
            r = self.post(
                f"/api/{self.tenant_id}/spokes/{spoke_id}/proxmox-command",
                json={"action": "__qa_probe__", "target": "spoke", "args": []},
            )
            if r.status_code == 403:
                self._fail(
                    f"Spoke '{name}' proxmox-command auth",
                    "proxmox",
                    "HTTP 403 — the current user is not an explicit tenant member. "
                    "A superadmin must add themselves as a tenant member, or the "
                    "require_tenant_member fix must be deployed (allows superadmin through).",
                )
            elif r.status_code in (200, 422):
                # 422 = auth passed, validation failed (probe action not a real action) — that's fine
                self._ok(
                    f"Spoke '{name}' proxmox-command auth",
                    "proxmox",
                    f"HTTP {r.status_code} — endpoint reachable and auth accepted",
                )
            else:
                self._warn(
                    f"Spoke '{name}' proxmox-command auth",
                    "proxmox",
                    f"HTTP {r.status_code} — unexpected status (not 200/403/422): {r.text[:120]}",
                )
            break  # one spoke is enough to validate auth; all use the same policy

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5 — USB / Dongle Configuration
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_usb(self) -> None:
        _section("Phase 5 — USB Dongle Configuration")

        r = self.get(f"/api/{self.tenant_id}/usb-vidpids")
        self._check("USB VID/PID list", "usb", r)

        r = self.get("/api/superadmin/global-usb-vidpids")
        if r.status_code in (200, 403):
            self._ok("Global USB VID/PIDs reachable", "usb")
        else:
            self._fail("Global USB VID/PIDs reachable", "usb", f"HTTP {r.status_code}")

        r = self.get("/api/superadmin/global-usb-ignored-vidpids")
        if r.status_code in (200, 403):
            self._ok("Global ignored VID/PIDs reachable", "usb")
        else:
            self._fail("Global ignored VID/PIDs reachable", "usb", f"HTTP {r.status_code}")

        r = self.get("/api/superadmin/discovered-usb-vidpids")
        if r.status_code in (200, 403):
            self._ok("Discovered USB VID/PIDs reachable", "usb")
        else:
            self._fail("Discovered USB VID/PIDs reachable", "usb", f"HTTP {r.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 6 — Auto-Provisioning (Critical Path)
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_provisioning(self) -> None:
        _section("Phase 6 — Auto-Provisioning (Critical Path ⭐)")

        # USB provisioning status
        r = self.get(f"/api/{self.tenant_id}/aggregate/usb-provisioning-status")
        res = self._check(
            "USB provisioning status",
            "provisioning",
            r,
            assert_keys=["total_dongles", "auto_provision_on", "spokes"],
        )
        if not res.passed:
            return

        prov_data = r.json()
        total_dongles: int = prov_data.get("total_dongles", 0)
        auto_on: bool = prov_data.get("auto_provision_on", False)
        spokes_prov: list[dict] = prov_data.get("spokes", [])

        if total_dongles == 0:
            self._warn(
                "Dongles detected",
                "provisioning",
                "total_dongles=0 — no USB dongles detected on any spoke",
            )
        else:
            self._ok("Dongles detected", "provisioning", f"total_dongles={total_dongles}")

        if not auto_on and total_dongles > 0:
            self._warn(
                "Auto-provisioning enabled",
                "provisioning",
                "auto_provision_on=false — enable it via POST /{tenant_id}/aggregate/toggle-auto-provision",
            )
        elif auto_on:
            self._ok("Auto-provisioning enabled", "provisioning")
        else:
            self._skip("Auto-provisioning enabled", "provisioning", "no dongles present")

        # ── Core QA check: dongles → VMs → reporting clients ─────────────────
        r = self.get(f"/api/{self.tenant_id}/qa/provisioning-check")
        res = self._check(
            "QA provisioning check (new API)",
            "provisioning",
            r,
            assert_keys=["overall_pass", "expected_clients", "actual_clients", "delta", "spokes"],
        )
        if not res.passed:
            return

        qa = r.json()
        expected = qa.get("expected_clients", 0)
        actual = qa.get("actual_clients", 0)
        delta = qa.get("delta", 0)
        overall_pass = qa.get("overall_pass", False)

        if expected == 0:
            self._skip(
                "Client count matches dongle count",
                "provisioning",
                "No dongles present — skip client count check",
            )
        elif overall_pass:
            self._ok(
                "Client count matches dongle count",
                "provisioning",
                f"expected={expected}, actual={actual}, delta={delta}",
            )
        else:
            self._fail(
                "Client count matches dongle count",
                "provisioning",
                f"expected={expected}, actual={actual}, delta={delta}",
            )

        # Per-spoke breakdown
        for spoke in qa.get("spokes", []):
            name = spoke.get("spoke_name", spoke.get("spoke_id", "?"))
            if spoke.get("pass"):
                self._ok(
                    f"Spoke '{name}' provisioning",
                    "provisioning",
                    f"dongles={spoke['dongle_count']}, vms={spoke['vm_count']}, "
                    f"clients={spoke['reporting_clients']}",
                )
            else:
                for issue in spoke.get("issues", ["unknown issue"]):
                    self._fail(f"Spoke '{name}' provisioning", "provisioning", issue)

        # Fleet reclone status
        r = self.get(f"/api/{self.tenant_id}/aggregate/fleet-reclone-status")
        self._check(
            "Fleet reclone status",
            "provisioning",
            r,
            warn_fn=lambda d: (
                f"fleet-reclone status={d.get('status')} (check for errors)"
                if d.get("status") == "error"
                else None
            ),
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 7 — Client Status & Simulations
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_clients(self) -> None:
        _section("Phase 7 — Client Status & Simulations")

        r = self.get("/api/aggregate/clients", params={"tenant_id": self.tenant_id})
        res = self._check("Aggregate client list", "clients", r, assert_keys=["clients"])
        if not res.passed:
            return

        client_list: list[dict] = r.json().get("clients", [])
        if not client_list:
            self._warn("Clients reporting", "clients", "No clients reporting — expected > 0 if dongles are present")
        else:
            self._ok("Clients reporting", "clients", f"{len(client_list)} client(s) total")

        # Check for active simulations
        active = sum(
            1 for c in client_list if c.get("active_simulations") or c.get("simulation_id")
        )
        if client_list and active == 0:
            self._warn(
                "Active simulations",
                "clients",
                "0 clients with active_simulations — check simulation.conf",
            )
        elif client_list:
            self._ok("Active simulations", "clients", f"{active}/{len(client_list)} clients simulating")

        # USB clients flagged
        usb_clients = sum(1 for c in client_list if c.get("has_usb"))
        self._ok("USB client attribution", "clients", f"{usb_clients} client(s) flagged has_usb=true")

        # Aggregate simulations
        r = self.get("/api/aggregate/simulations", params={"tenant_id": self.tenant_id})
        self._check("Aggregate simulations", "clients", r)

        # Hardware breakdown
        r = self.get("/api/aggregate/dashboard", params={"tenant_id": self.tenant_id})
        res2 = self._check("Dashboard hardware breakdown", "clients", r, assert_keys=["hardware_breakdown"])
        if res2.passed:
            bd = r.json().get("hardware_breakdown", {})
            self._ok("Hardware breakdown populated", "clients", str(bd) if bd else "empty")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8 — Commands & Control
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_commands(self) -> None:
        _section("Phase 8 — Commands & Control")

        r = self.get(f"/api/{self.tenant_id}/commands")
        res = self._check("Command queue readable", "commands", r)

        # Inspect the command queue for stuck or expired commands
        if res.passed:
            cmds = r.json() if isinstance(r.json(), list) else r.json().get("commands", [])
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            pending = [c for c in cmds if c.get("status") == "queued"]
            expired = []
            old_pending = []
            for c in pending:
                exp = c.get("expires_at")
                cre = c.get("created_at")
                if exp:
                    try:
                        exp_dt = datetime.datetime.fromisoformat(exp.replace("Z", "+00:00"))
                        if exp_dt < now_utc:
                            expired.append(c)
                    except Exception:
                        pass
                if cre:
                    try:
                        cre_dt = datetime.datetime.fromisoformat(cre.replace("Z", "+00:00"))
                        age_s = (now_utc - cre_dt).total_seconds()
                        if age_s > 300:  # >5 min in queue = likely stuck
                            old_pending.append((c, int(age_s)))
                    except Exception:
                        pass
            if expired:
                self._warn(
                    "Command queue — expired commands",
                    "commands",
                    f"{len(expired)} expired command(s) still in queue "
                    f"(types: {list({c.get('type','?') for c in expired})}) — "
                    "spoke may have been offline when commands were issued",
                    raw_data={"expired_commands": [
                        {k: c.get(k) for k in ("id", "type", "spoke_id", "status", "created_at", "expires_at")}
                        for c in expired[:10]
                    ]},
                )
            elif pending:
                self._ok("Command queue — expired commands", "commands",
                         f"{len(pending)} pending command(s), none expired")
            else:
                self._ok("Command queue — expired commands", "commands", "queue empty or all executed")

            if old_pending:
                self._warn(
                    "Command queue — stuck pending commands",
                    "commands",
                    f"{len(old_pending)} command(s) pending >5 min "
                    f"(oldest: {old_pending[0][1]}s) — spoke may not be polling",
                    raw_data={"stuck_commands": [
                        {**{k: c.get(k) for k in ("id", "type", "spoke_id", "status", "created_at")},
                         "age_s": age_s}
                        for c, age_s in old_pending[:10]
                    ]},
                )

        r = self.get("/api/aggregate/api-server", params={"tenant_id": self.tenant_id})
        self._check("Aggregate API server status", "commands", r)

        # Per-spoke audit logs
        r = self.get(f"/api/{self.tenant_id}/spokes")
        if r.status_code == 200:
            spokes = r.json().get("spokes", [])
            for spoke in spokes[:2]:
                sid = spoke.get("id") or spoke.get("spoke_id", "")
                if sid:
                    ra = self.get(f"/api/{self.tenant_id}/spokes/{sid}/audit")
                    self._check(
                        f"Spoke '{spoke.get('spoke_name') or sid}' audit log",
                        "commands",
                        ra,
                    )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 9 — Settings & Configuration
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_settings(self) -> None:
        _section("Phase 9 — Settings & Configuration")

        r = self.get(f"/api/{self.tenant_id}/settings/processing-mode")
        self._check("Processing mode", "settings", r)

        r = self.get(f"/api/{self.tenant_id}/processing-summary")
        self._check("Processing summary", "settings", r)

        r = self.get(f"/api/{self.tenant_id}/config/simulation-conf")
        self._check("Simulation config", "settings", r)

        r = self.get(f"/api/{self.tenant_id}/config/sim-conf-override")
        if r.status_code in (200, 404):
            self._ok("Sim conf override endpoint", "settings")
        else:
            self._fail("Sim conf override endpoint", "settings", f"HTTP {r.status_code}")

        r = self.get(f"/api/{self.tenant_id}/config/user-conf-override")
        if r.status_code in (200, 404):
            self._ok("User conf override endpoint", "settings")
        else:
            self._fail("User conf override endpoint", "settings", f"HTTP {r.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 10 — Central / Aruba Integration
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_central(self) -> None:
        _section("Phase 10 — Aruba Central Integration")

        r = self.get("/central/available")
        res = self._check("Central available", "central", r)
        if res.passed:
            avail = r.json()
            if not avail.get("available"):
                self._skip("Central connection", "central", "Central not configured — skipping Central checks")
                return
            self._ok("Central configured", "central")

        r = self.get("/api/aggregate/central-status")
        self._check("Central status", "central", r)

        r = self.get("/api/aggregate/central", params={"tenant_id": self.tenant_id})
        self._check("Aggregate Central", "central", r)

        r = self.get(f"/api/{self.tenant_id}/aggregate/central-sites-config")
        self._check("Central sites config", "central", r)

        r = self.get(f"/api/{self.tenant_id}/aggregate/register-central-webhook")
        if r.status_code in (200, 404):
            self._ok("Central webhook status", "central")
        else:
            self._fail("Central webhook status", "central", f"HTTP {r.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 11 — Backup & Restore
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_backup(self) -> None:
        _section("Phase 11 — Backup & Restore")

        r = self.get("/api/backup/config")
        self._check("Backup config readable", "backup", r)

        r = self.get("/api/backup/status")
        self._check("Backup status", "backup", r)

        r = self.get("/api/backup/templates")
        self._check("Backup templates", "backup", r)

        r = self.get("/api/backup/installer/sas-token")
        if r.status_code in (200, 400, 403, 404):
            self._ok("Installer SAS token endpoint reachable", "backup")
        else:
            self._fail("Installer SAS token endpoint reachable", "backup", f"HTTP {r.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 12 — T3 / MAC Profiles
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_t3(self) -> None:
        _section("Phase 12 — T3 / MAC Profiles")

        r = self.get("/api/oui-pool")
        self._check("OUI pool", "t3", r)

        r = self.get(f"/api/{self.tenant_id}/spokes")
        if r.status_code == 200:
            spokes = r.json().get("spokes", [])
            for spoke in spokes[:2]:
                sid = spoke.get("id") or spoke.get("spoke_id", "")
                name = spoke.get("spoke_name") or sid
                if sid:
                    rt = self.get(f"/api/{self.tenant_id}/spokes/{sid}/t3/mac-profile")
                    if rt.status_code in (200, 404):
                        self._ok(f"Spoke '{name}' T3 MAC profile endpoint", "t3")
                    else:
                        self._fail(f"Spoke '{name}' T3 MAC profile endpoint", "t3", f"HTTP {rt.status_code}")

                    rd = self.get(f"/api/{self.tenant_id}/spokes/{sid}/t3/devices")
                    if rd.status_code in (200, 404):
                        self._ok(f"Spoke '{name}' T3 devices endpoint", "t3")
                    else:
                        self._fail(f"Spoke '{name}' T3 devices endpoint", "t3", f"HTTP {rd.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 13 — Health & QA System Check
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_health(self) -> None:
        _section("Phase 13 — System Health & QA Summary")

        r = self.get("/api/health")
        self._check("Hub health endpoint", "health", r)

        r = self.get("/api/aggregate/qa/system-health", params={"tenant_id": self.tenant_id})
        res = self._check(
            "QA system health (new API)",
            "health",
            r,
            assert_keys=["hub_ok", "all_ok", "spokes_total", "spokes_online"],
        )
        if res.passed:
            data = r.json()
            if data.get("all_ok"):
                self._ok("QA system health all_ok", "health",
                         f"spokes={data['spokes_online']}/{data['spokes_total']}, "
                         f"proxmox={data.get('proxmox_agents_connected')}/{data['spokes_total']}, "
                         f"clients={data.get('total_clients')}")
            else:
                for issue in data.get("issues", ["all_ok=false"]):
                    self._fail("QA system health all_ok", "health", issue)

        r = self.get("/api/aggregate/api-server", params={"tenant_id": self.tenant_id})
        self._check("API server aggregate", "health", r)

        # Kill switch check
        r = self.get("/api/superadmin/gkill-state")
        if r.status_code in (200, 403):
            self._ok("Global kill switch state reachable", "health")
        else:
            self._fail("Global kill switch state reachable", "health", f"HTTP {r.status_code}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 14 — Background Task Validation
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_background(self) -> None:
        _section("Phase 14 — Background Task Validation")

        # Heartbeat: at least one spoke should have been seen recently
        r = self.get(f"/api/{self.tenant_id}/spokes")
        if r.status_code == 200:
            spokes = r.json().get("spokes", [])
            stale_threshold = 300  # seconds
            now = time.time()
            for spoke in spokes:
                name = spoke.get("spoke_name") or spoke.get("id", "?")
                last_seen_str = spoke.get("last_seen")
                if last_seen_str:
                    try:
                        ls = datetime.datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                        age = (datetime.datetime.now(datetime.timezone.utc) - ls).total_seconds()
                        if age > stale_threshold:
                            self._fail(
                                f"Spoke '{name}' heartbeat fresh",
                                "background",
                                f"last_seen {int(age)}s ago (threshold {stale_threshold}s)",
                            )
                        else:
                            self._ok(f"Spoke '{name}' heartbeat fresh", "background",
                                     f"last_seen {int(age)}s ago")
                    except Exception:
                        self._warn(f"Spoke '{name}' heartbeat", "background",
                                   "Could not parse last_seen timestamp")
                else:
                    self._fail(f"Spoke '{name}' heartbeat fresh", "background", "last_seen is null")

        # No unexpected pending recovery commands
        r = self.get(f"/api/{self.tenant_id}/commands")
        if r.status_code == 200:
            cmds = r.json() if isinstance(r.json(), list) else r.json().get("commands", [])
            recovery_cmds = [c for c in cmds if c.get("type") == "recovery"]
            if recovery_cmds:
                self._warn(
                    "Auto-recovery commands",
                    "background",
                    f"{len(recovery_cmds)} recovery command(s) queued — spokes may be struggling",
                )
            else:
                self._ok("No unexpected recovery commands queued", "background")

        # ── Simultaneous-offline pattern detector ─────────────────────────────
        # When ALL spokes drop offline at the same time it is almost always a
        # hub-level problem (asyncio event loop blocked by synchronous CIFS I/O
        # or store.get_tenant) rather than individual spoke failures.  This was
        # the root cause of the 12-minute all-spokes-offline incident.
        # Re-uses the same spoke list fetched above when possible.
        r2 = self.get(f"/api/{self.tenant_id}/spokes")
        if r2.status_code == 200:
            all_spokes = r2.json().get("spokes", [])
            total_sp = len(all_spokes)
            offline_sp = [
                s for s in all_spokes
                if not (s.get("online") or s.get("status") == "online")
            ]
            if total_sp >= 2 and len(offline_sp) == total_sp:
                self._fail(
                    "All-spokes-simultaneous-offline",
                    "background",
                    f"All {total_sp} spokes offline at the same time — this pattern "
                    "indicates a hub-level event-loop block or CIFS stall, not individual "
                    "spoke failures. Check hub_loop_lag_ms in phase_proxmox results and "
                    "confirm store.get_tenant / store.save_spoke are running in executor.",
                )
            elif total_sp >= 2 and len(offline_sp) > total_sp // 2:
                self._warn(
                    "Majority-spokes-simultaneous-offline",
                    "background",
                    f"{len(offline_sp)}/{total_sp} spokes offline at once — majority offline "
                    "suggests a hub-level issue rather than independent spoke failures; "
                    "check hub_loop_lag_ms",
                )
            elif total_sp >= 2:
                self._ok(
                    "All-spokes-simultaneous-offline",
                    "background",
                    f"Pattern not triggered — {total_sp - len(offline_sp)}/{total_sp} spokes online",
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 15 — VM Teardown
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_teardown(self) -> None:
        _section("Phase 15 — VM Teardown (⚠ Destructive)")

        # Step 1: trigger teardown
        r = self.post(f"/api/{self.tenant_id}/qa/teardown-all-vms")
        res = self._check(
            "Queue teardown of all sim VMs",
            "teardown",
            r,
            assert_keys=["ok", "total_vms_queued", "spokes"],
        )
        if not res.passed:
            return

        td = r.json()
        total_queued: int = td.get("total_vms_queued", 0)
        if total_queued == 0:
            self._skip(
                "VMs queued for deletion",
                "teardown",
                "No sim VMs found in telemetry (vmid > 9000) — nothing to tear down",
            )
            return

        self._ok(
            "VMs queued for deletion",
            "teardown",
            f"Queued delete_vm for {total_queued} VM(s) across {len(td.get('spokes', []))} spoke(s)",
        )

        # Step 2: poll teardown-status until complete (5 min timeout)
        timeout_s = 300
        poll_interval_s = 10
        deadline = time.monotonic() + timeout_s

        while time.monotonic() < deadline:
            r = self.get(f"/api/{self.tenant_id}/qa/teardown-status")
            if r.status_code != 200:
                self._warn(
                    "Teardown status poll",
                    "teardown",
                    f"HTTP {r.status_code} during poll",
                )
                break

            status = r.json()
            remaining = status.get("total_remaining", 0)
            if status.get("complete"):
                self._ok(
                    "All sim VMs deleted",
                    "teardown",
                    "total_remaining=0 across all spokes",
                )
                return

            elapsed_s = int(timeout_s - (deadline - time.monotonic()))
            print(f"    ⏳  {remaining} VM(s) still present — waiting... ({elapsed_s}s elapsed)")
            time.sleep(poll_interval_s)

        # Timed out — report what's left
        r = self.get(f"/api/{self.tenant_id}/qa/teardown-status")
        if r.status_code == 200:
            status = r.json()
            remaining = status.get("total_remaining", 0)
            spokes_detail = ", ".join(
                f"{s.get('spoke_name', s.get('spoke_id', '?'))}={s.get('sim_vms_remaining', '?')}"
                for s in status.get("spokes", [])
                if s.get("sim_vms_remaining", 0) > 0
            )
            self._fail(
                "All sim VMs deleted",
                "teardown",
                f"Timed out after {timeout_s}s — {remaining} VM(s) still present: {spokes_detail}",
            )
        else:
            self._fail("All sim VMs deleted", "teardown", f"Timeout + status poll failed (HTTP {r.status_code})")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 16 — Auto-Provisioning End-to-End
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_autoprov_e2e(self) -> None:
        _section("Phase 16 — Auto-Provisioning End-to-End (⚠ Long-running)")

        # Step 1: verify dongles are present before enabling
        r = self.get(f"/api/{self.tenant_id}/aggregate/usb-provisioning-status")
        if r.status_code != 200:
            self._fail("Dongles present before autoprov test", "autoprov_e2e", f"HTTP {r.status_code}")
            return

        prov = r.json()
        total_dongles: int = prov.get("total_dongles", 0)
        if total_dongles == 0:
            self._skip(
                "Auto-provisioning E2E",
                "autoprov_e2e",
                "No USB dongles detected — cannot run E2E provisioning test",
            )
            return

        self._ok(
            "Dongles present",
            "autoprov_e2e",
            f"total_dongles={total_dongles} — proceeding to enable auto-provisioning",
        )

        # Step 2: enable auto-provisioning fleet-wide
        r = self.post(f"/api/{self.tenant_id}/qa/enable-autoprov")
        res = self._check(
            "Enable Auto-Provisioning on all spokes",
            "autoprov_e2e",
            r,
            assert_keys=["ok", "expected_clients", "updated_spokes"],
        )
        if not res.passed:
            return

        ap = r.json()
        expected: int = ap.get("expected_clients", 0)
        self._ok(
            "Auto-Provisioning enabled",
            "autoprov_e2e",
            f"expected_clients={expected} ({ap.get('updated_spokes', 0)} spoke(s) updated)",
        )

        if expected == 0:
            self._skip(
                "Wait for clients online",
                "autoprov_e2e",
                "expected_clients=0 — no dongles to provision",
            )
            return

        # Step 3: poll provisioning-check until all clients are online (10 min)
        timeout_s = 600
        poll_interval_s = 15
        deadline = time.monotonic() + timeout_s

        while time.monotonic() < deadline:
            r = self.get(f"/api/{self.tenant_id}/qa/provisioning-check")
            if r.status_code != 200:
                self._warn("Client online poll", "autoprov_e2e", f"HTTP {r.status_code} during poll")
                break

            qa = r.json()
            actual = qa.get("actual_clients", 0)
            overall_pass = qa.get("overall_pass", False)

            if overall_pass and actual >= expected:
                self._ok(
                    f"All {expected} clients online",
                    "autoprov_e2e",
                    f"actual={actual}, expected={expected}, delta={qa.get('delta', 0)}",
                )
                # Per-spoke breakdown
                for spoke in qa.get("spokes", []):
                    name = spoke.get("spoke_name", spoke.get("spoke_id", "?"))
                    if spoke.get("pass"):
                        self._ok(
                            f"Spoke '{name}' fully provisioned",
                            "autoprov_e2e",
                            f"dongles={spoke['dongle_count']}, vms={spoke['vm_count']}, "
                            f"clients={spoke['reporting_clients']}",
                        )
                    else:
                        for issue in spoke.get("issues", ["unknown issue"]):
                            self._warn(f"Spoke '{name}' provisioning", "autoprov_e2e", issue)
                return

            elapsed_s = int(timeout_s - (deadline - time.monotonic()))
            print(f"    ⏳  {actual}/{expected} clients online — waiting... ({elapsed_s}s elapsed)")
            time.sleep(poll_interval_s)

        # Timed out
        r = self.get(f"/api/{self.tenant_id}/qa/provisioning-check")
        if r.status_code == 200:
            qa = r.json()
            actual = qa.get("actual_clients", 0)
            delta = qa.get("delta", 0)
            spoke_details = []
            for s in qa.get("spokes", []):
                if not s.get("pass"):
                    name = s.get("spoke_name", s.get("spoke_id", "?"))
                    spoke_details.append(
                        f"{name}: dongles={s['dongle_count']}, vms={s['vm_count']}, "
                        f"clients={s['reporting_clients']}"
                    )
            self._fail(
                f"All {expected} clients online",
                "autoprov_e2e",
                f"Timed out after {timeout_s}s — actual={actual}/{expected}. " +
                " | ".join(spoke_details),
            )
        else:
            self._fail(
                f"All {expected} clients online",
                "autoprov_e2e",
                f"Timeout + final poll failed (HTTP {r.status_code})",
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 17 — Full Simulation Cycle (teardown → disable → enable → verify)
    # ═══════════════════════════════════════════════════════════════════════════

    def phase_sim_cycle(self) -> None:
        _section("Phase 17 — Full Simulation Cycle (⚠ Destructive + Long-running)")
        MODULE = "sim_cycle"

        # Step 1: verify dongles are present
        r = self.get(f"/api/{self.tenant_id}/aggregate/usb-provisioning-status")
        if r.status_code != 200:
            self._fail("Dongles present", MODULE, f"HTTP {r.status_code}")
            return
        prov = r.json()
        total_dongles: int = prov.get("total_dongles", 0)
        if total_dongles == 0:
            self._skip("Simulation cycle", MODULE, "No USB dongles detected — cannot run simulation cycle")
            return
        spoke_detail = ", ".join(
            f"{s.get('spoke_name', s.get('spoke_id', '?'))}: {s.get('dongle_count', 0)} dongle(s)"
            for s in prov.get("spokes", [])
            if s.get("dongle_count", 0) > 0
        )
        self._ok("Dongles present", MODULE, f"total_dongles={total_dongles} — {spoke_detail}")

        # Step 2: disable auto-provisioning fleet-wide
        r = self.post(
            f"/api/{self.tenant_id}/aggregate/toggle-auto-provision",
            json={"enable": False},
        )
        res = self._check("Disable Auto-Provisioning fleet-wide", MODULE, r, assert_keys=["ok"])
        if not res.passed:
            return
        self._ok(
            "Auto-Provisioning disabled",
            MODULE,
            f"updated_spokes={r.json().get('updated_spokes', '?')}",
        )

        # Step 3: clear the command queue so no stale config_update commands interfere
        r = self.delete(f"/api/{self.tenant_id}/commands")
        if r.status_code not in (200, 204):
            self._warn("Clear command queue", MODULE, f"HTTP {r.status_code} — continuing anyway")
        else:
            body = r.json() if r.status_code == 200 else {}
            cleared = body.get("cleared") or body.get("detail", "queue cleared")
            self._ok("Command queue cleared", MODULE, str(cleared))

        # Step 4: trigger teardown of all sim VMs
        r = self.post(f"/api/{self.tenant_id}/qa/teardown-all-vms")
        res = self._check(
            "Queue teardown of all sim VMs", MODULE, r,
            assert_keys=["ok", "total_vms_queued", "spokes"],
        )
        if not res.passed:
            return
        td = r.json()
        total_queued: int = td.get("total_vms_queued", 0)
        if total_queued == 0:
            self._skip(
                "VMs queued for deletion", MODULE,
                "No sim VMs found (vmid > 9000) — already clean",
            )
        else:
            self._ok(
                "VMs queued for deletion", MODULE,
                f"Queued delete_vm for {total_queued} VM(s) across {len(td.get('spokes', []))} spoke(s)",
            )

            # Step 5: poll until all VMs are deleted
            timeout_s = 300
            poll_interval_s = 10
            deadline = time.monotonic() + timeout_s
            teardown_ok = False

            while time.monotonic() < deadline:
                r = self.get(f"/api/{self.tenant_id}/qa/teardown-status")
                if r.status_code != 200:
                    self._warn("Teardown status poll", MODULE, f"HTTP {r.status_code} during poll")
                    break
                status = r.json()
                if status.get("complete"):
                    self._ok("All sim VMs deleted", MODULE, "total_remaining=0 across all spokes")
                    teardown_ok = True
                    break
                remaining = status.get("total_remaining", 0)
                elapsed_s = int(timeout_s - (deadline - time.monotonic()))
                print(f"    ⏳  {remaining} VM(s) still present — waiting... ({elapsed_s}s elapsed)")
                time.sleep(poll_interval_s)

            if not teardown_ok:
                r = self.get(f"/api/{self.tenant_id}/qa/teardown-status")
                if r.status_code == 200:
                    status = r.json()
                    remaining = status.get("total_remaining", 0)
                    spoke_info = ", ".join(
                        f"{s.get('spoke_name', s.get('spoke_id', '?'))}={s.get('sim_vms_remaining', '?')}"
                        for s in status.get("spokes", [])
                        if s.get("sim_vms_remaining", 0) > 0
                    )
                    self._fail(
                        "All sim VMs deleted", MODULE,
                        f"Timed out after {timeout_s}s — {remaining} VM(s) still present: {spoke_info}",
                    )
                else:
                    self._fail(
                        "All sim VMs deleted", MODULE,
                        f"Timeout + teardown status poll failed (HTTP {r.status_code})",
                    )
                return

        # Step 6: enable auto-provisioning fleet-wide
        r = self.post(f"/api/{self.tenant_id}/qa/enable-autoprov")
        res = self._check(
            "Enable Auto-Provisioning fleet-wide", MODULE, r,
            assert_keys=["ok", "expected_clients", "updated_spokes"],
        )
        if not res.passed:
            return
        ap = r.json()
        expected: int = ap.get("expected_clients", 0)
        spoke_detail = ", ".join(
            f"{s.get('spoke_name', s.get('spoke_id', '?'))}: {s.get('dongle_count', 0)} dongle(s)"
            for s in ap.get("spokes", [])
        )
        self._ok(
            "Auto-Provisioning enabled", MODULE,
            f"expected_clients={expected} ({ap.get('updated_spokes', 0)} spoke(s)) — {spoke_detail}",
        )

        if expected == 0:
            self._skip("Wait for clients online", MODULE, "expected_clients=0 — no dongles to provision")
            return

        # Step 7: poll provisioning-check until all clients are online (10 min)
        timeout_s = 600
        poll_interval_s = 15
        deadline = time.monotonic() + timeout_s

        while time.monotonic() < deadline:
            r = self.get(f"/api/{self.tenant_id}/qa/provisioning-check")
            if r.status_code != 200:
                self._warn("Client online poll", MODULE, f"HTTP {r.status_code} during poll")
                break
            qa = r.json()
            actual = qa.get("actual_clients", 0)
            if qa.get("overall_pass") and actual >= expected:
                per_spoke = ", ".join(
                    f"{s.get('spoke_name', s.get('spoke_id', '?'))}: {s['reporting_clients']}/{s['dongle_count']}"
                    for s in qa.get("spokes", [])
                )
                self._ok(
                    f"All {expected} clients online", MODULE,
                    f"actual={actual}, expected={expected} — {per_spoke}",
                )
                break
            elapsed_s = int(timeout_s - (deadline - time.monotonic()))
            print(f"    ⏳  {actual}/{expected} clients online — waiting... ({elapsed_s}s elapsed)")
            time.sleep(poll_interval_s)
        else:
            r = self.get(f"/api/{self.tenant_id}/qa/provisioning-check")
            if r.status_code == 200:
                qa = r.json()
                actual = qa.get("actual_clients", 0)
                incomplete = ", ".join(
                    f"{s.get('spoke_name', s.get('spoke_id', '?'))}: {s['reporting_clients']}/{s['dongle_count']}"
                    for s in qa.get("spokes", [])
                    if not s.get("pass")
                )
                self._fail(
                    f"All {expected} clients online", MODULE,
                    f"Timed out after {timeout_s}s — {actual}/{expected} online. Incomplete: {incomplete}",
                )
            else:
                self._fail(
                    f"All {expected} clients online", MODULE,
                    f"Timeout + final poll failed (HTTP {r.status_code})",
                )
            return

        # Step 8: verify no over-provisioning (vm_count <= dongle_count per spoke)
        r = self.get(f"/api/aggregate/proxmox?tenant_id={self.tenant_id}")
        if r.status_code != 200:
            self._warn("No over-provisioning check", MODULE, f"HTTP {r.status_code} fetching proxmox aggregate")
        else:
            hosts = r.json().get("hosts", [])
            with_dongles = [h for h in hosts if (h.get("usb_count") or 0) > 0]
            if not with_dongles:
                self._skip("No over-provisioning (vm_count ≤ dongle_count)", MODULE, "No spokes with dongles in proxmox aggregate")
            else:
                over = [h for h in with_dongles if (h.get("vm_count") or 0) > (h.get("usb_count") or 0)]
                per_spoke = "; ".join(
                    f"{h.get('spoke_name', h.get('spoke_id', '?'))}: vms={h.get('vm_count', '?')}/{h.get('usb_count', '?')} dongles"
                    + (
                        f" CPU-pacing({h['proxmox']['provision_halt']['cpu_pct']}%≥{h['proxmox']['provision_halt']['cpu_threshold']}%)"
                        if h.get("proxmox", {}).get("provision_halt", {}).get("halted")
                        and h["proxmox"]["provision_halt"].get("reason") == "pacing"
                        else ""
                    )
                    for h in with_dongles
                )
                if over:
                    self._fail(
                        "No over-provisioning (vm_count ≤ dongle_count)", MODULE,
                        f"Over-provisioned on {len(over)}/{len(with_dongles)} spoke(s) — {per_spoke}",
                    )
                else:
                    self._ok(
                        "No over-provisioning (vm_count ≤ dongle_count)", MODULE,
                        f"vm_count ≤ dongle_count on all spokes — {per_spoke}",
                    )

        # Step 9: verify CPU provisioning throttle (provision_halt.reason='pacing')
        r = self.get(f"/api/aggregate/proxmox?tenant_id={self.tenant_id}")
        if r.status_code != 200:
            self._warn("CPU provisioning throttle", MODULE, f"HTTP {r.status_code} fetching proxmox aggregate")
        else:
            hosts = r.json().get("hosts", [])
            online = [h for h in hosts if h.get("spoke_online")]
            if not online:
                self._skip("CPU provisioning throttle (provision_halt)", MODULE, "No online spokes")
            else:
                pacing = [
                    h for h in online
                    if h.get("proxmox", {}).get("provision_halt", {}).get("halted")
                    and h["proxmox"]["provision_halt"].get("reason") == "pacing"
                ]
                per_spoke = "; ".join(
                    (
                        f"{h.get('spoke_name', h.get('spoke_id', '?'))}: PACING "
                        f"cpu_pct={h['proxmox']['provision_halt'].get('cpu_pct', '?')}% "
                        f"thr={h['proxmox']['provision_halt'].get('cpu_threshold', '?')}% "
                        f"1h_avg={float(h['proxmox'].get('cpu_1h_avg', 0) or 0):.1f}%"
                        if h.get("proxmox", {}).get("provision_halt", {}).get("halted")
                        else f"{h.get('spoke_name', h.get('spoke_id', '?'))}: ok "
                        f"cpu_1h_avg={float(h.get('proxmox', {}).get('cpu_1h_avg', 0) or 0):.1f}%"
                    )
                    for h in online
                )
                if pacing:
                    self._ok(
                        "CPU provisioning throttle (provision_halt)",
                        MODULE,
                        f"CPU pacing active on {len(pacing)}/{len(online)} spoke(s) — {per_spoke}",
                    )
                else:
                    self._warn(
                        "CPU provisioning throttle (provision_halt)",
                        MODULE,
                        f"No CPU pacing active (CPU below provision threshold) — {per_spoke}",
                    )

        # Step 10: report CPU 1h avg vs delete threshold (VM teardown fires above this)
        r = self.get(f"/api/aggregate/proxmox?tenant_id={self.tenant_id}")
        if r.status_code != 200:
            self._warn("CPU delete-threshold teardown check", MODULE, f"HTTP {r.status_code} fetching proxmox aggregate")
        else:
            hosts = r.json().get("hosts", [])
            online = [h for h in hosts if h.get("spoke_online")]
            if not online:
                self._skip("CPU delete-threshold teardown check", MODULE, "No online spokes")
            else:
                above_threshold = []
                lines = []
                for h in online:
                    name = h.get("spoke_name", h.get("spoke_id", "?"))
                    cpu_avg = (h.get("proxmox") or {}).get("cpu_1h_avg")
                    ph = (h.get("proxmox") or {}).get("provision_halt") or {}
                    del_thr = float(ph.get("cpu_threshold") or 90)
                    cpu_str = f"{float(cpu_avg):.1f}%" if cpu_avg is not None else "n/a"
                    lines.append(f"{name}: cpu_1h_avg={cpu_str} (delete_thr={del_thr:.0f}%)")
                    if cpu_avg is not None and float(cpu_avg) >= del_thr:
                        above_threshold.append(name)
                detail_str = "; ".join(lines)
                if above_threshold:
                    self._ok(
                        "CPU delete-threshold teardown check",
                        MODULE,
                        f"cpu_1h_avg ≥ delete_thr on {', '.join(above_threshold)} — {detail_str}",
                    )
                else:
                    self._warn(
                        "CPU delete-threshold teardown check",
                        MODULE,
                        f"cpu_1h_avg below delete threshold on all spokes (teardown not triggered) — {detail_str}",
                    )

    # ═══════════════════════════════════════════════════════════════════════════
    # Run all phases
    # ═══════════════════════════════════════════════════════════════════════════

    def run(self, phases: list[str] | None = None) -> int:
        all_phases = {
            "auth":         self.phase_auth,
            "hub":          self.phase_hub_health,
            "spokes":       self.phase_spokes,
            "proxmox":      self.phase_proxmox,
            "usb":          self.phase_usb,
            "provisioning": self.phase_provisioning,
            "clients":      self.phase_clients,
            "commands":     self.phase_commands,
            "settings":     self.phase_settings,
            "central":      self.phase_central,
            "backup":       self.phase_backup,
            "t3":           self.phase_t3,
            "health":       self.phase_health,
            "background":   self.phase_background,
            "teardown":     self.phase_teardown,
            "autoprov_e2e": self.phase_autoprov_e2e,
            "sim_cycle":    self.phase_sim_cycle,
        }

        selected = phases if phases else list(all_phases.keys())
        unknown = [p for p in selected if p not in all_phases]
        if unknown:
            print(f"Unknown phases: {unknown}. Valid: {list(all_phases.keys())}", file=sys.stderr)
            return 2

        # Bootstrap auth if we're not running the full auth phase — every phase
        # needs a valid token + tenant_id (populated by the key exchange).
        if not self.token and "auth" not in selected:
            r = self._http().post("/api/qa/auth", json={"qa_api_key": self.qa_key})
            if r.status_code != 200:
                print(f"ERROR: QA key exchange failed — HTTP {r.status_code}: {r.text[:200]}", file=sys.stderr)
                return 2
            data = r.json()
            self.token = data.get("access_token", "")
            self.tenant_id = data.get("tenant_id", "")
            if not self.token:
                print(f"ERROR: No access_token in key exchange response: {data}", file=sys.stderr)
                return 2

        start = time.monotonic()
        for phase_name in selected:
            try:
                all_phases[phase_name]()
            except SystemExit:
                raise
            except Exception as exc:  # noqa: BLE001
                self._fail(f"Phase {phase_name} (unhandled error)", phase_name, str(exc))

        elapsed = time.monotonic() - start
        return self._report(elapsed)

    # ═══════════════════════════════════════════════════════════════════════════
    # Report
    # ═══════════════════════════════════════════════════════════════════════════

    def _report(self, elapsed: float) -> int:
        passed   = [r for r in self.results if r.passed and not r.skipped and not r.warning]
        failed   = [r for r in self.results if not r.passed and not r.skipped]
        warnings = [r for r in self.results if r.warning]
        skipped  = [r for r in self.results if r.skipped]

        print()
        print(BOLD("━" * 70))
        print(BOLD("  CLIENT-SIM QA REPORT"))
        print(BOLD("━" * 70))

        for r in self.results:
            if r.skipped:
                icon = YELLOW("  SKIP")
            elif r.warning:
                icon = YELLOW("  WARN")
            elif r.passed:
                icon = GREEN("  PASS")
            else:
                icon = RED("  FAIL")
            line = f"{icon}  {r.name}"
            if r.detail:
                line += DIM(f"  ({r.detail})")
            print(line)
            if self.dump_on_fail and r.raw_data and (not r.passed or r.warning):
                print(DIM("      raw_data: " + json.dumps(r.raw_data, indent=6, default=str)))

        print()
        print(BOLD("━" * 70))
        summary_parts = [
            GREEN(f"  {len(passed)} passed"),
            RED(f"  {len(failed)} failed") if failed else DIM(f"  {len(failed)} failed"),
            YELLOW(f"  {len(warnings)} warnings"),
            DIM(f"  {len(skipped)} skipped"),
        ]
        print("  ".join(summary_parts))
        print(DIM(f"  Completed in {elapsed:.1f}s"))
        print(BOLD("━" * 70))

        if failed:
            print()
            print(RED(BOLD("  FAILURES:")))
            for r in failed:
                print(f"    {RED('✗')} [{r.phase}] {r.name}")
                if r.detail:
                    print(f"      {DIM(r.detail)}")
                if self.dump_on_fail and r.raw_data:
                    print(DIM("      raw_data: " + json.dumps(r.raw_data, indent=6, default=str)))

        return 1 if failed else 0

    def report_json(self, elapsed: float) -> int:
        failed = [r for r in self.results if not r.passed and not r.skipped]
        output = {
            "passed": sum(1 for r in self.results if r.passed and not r.skipped and not r.warning),
            "failed": len(failed),
            "warnings": sum(1 for r in self.results if r.warning),
            "skipped": sum(1 for r in self.results if r.skipped),
            "elapsed_s": round(elapsed, 2),
            "all_passed": len(failed) == 0,
            "results": [
                {
                    "phase": r.phase,
                    "name": r.name,
                    "passed": r.passed,
                    "skipped": r.skipped,
                    "warning": r.warning,
                    "detail": r.detail,
                    # raw_data only included for FAIL/WARN to keep JSON compact
                    **({"raw_data": r.raw_data} if r.raw_data and (not r.passed or r.warning) else {}),
                }
                for r in self.results
            ],
        }
        print(json.dumps(output, indent=2))
        return 1 if failed else 0


# ── CLI helpers ───────────────────────────────────────────────────────────────

def _section(title: str) -> None:
    print()
    print(BOLD(f"\n  ── {title} ──"))


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Client-Sim end-to-end QA runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--url",      default=os.getenv("CS_HUB_URL",  "https://localhost:8443"),
                   help="Hub base URL (default: CS_HUB_URL env or https://localhost:8443)")
    p.add_argument("--qa-key",   default=os.getenv("CS_QA_API_KEY", ""),
                   help="QA API key (default: CS_QA_API_KEY env var). "
                        "Generate one via POST /api/superadmin/qa-api-keys (superadmin only).")
    p.add_argument("--no-verify", action="store_true",
                   help="Disable TLS certificate verification (self-signed certs)")
    p.add_argument("--json", action="store_true",
                   help="Output results as JSON (for CI / Copilot parsing)")
    p.add_argument("--phases", default="",
                   help="Comma-separated list of phases to run "
                        "(auth,hub,spokes,proxmox,usb,provisioning,clients,"
                        "commands,settings,central,backup,t3,health,background)")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="HTTP request timeout in seconds (default: 15)")
    p.add_argument("--dump-on-fail", action="store_true",
                   help="Print raw API response data under each FAIL/WARN result "
                        "(useful for sharing with Copilot for root-cause diagnosis)")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    if not args.qa_key:
        print("ERROR: --qa-key or CS_QA_API_KEY is required.", file=sys.stderr)
        print("       Generate a key: POST /api/superadmin/qa-api-keys (superadmin only)", file=sys.stderr)
        sys.exit(2)

    if args.json:
        global _USE_COLOR
        _USE_COLOR = False

    phases = [p.strip() for p in args.phases.split(",") if p.strip()] if args.phases else None

    print(BOLD(f"\n  Client-Sim QA Runner"))
    print(DIM(f"  Hub: {args.url}  |  Key: {args.qa_key[:8]}…"))

    runner = QARunner(
        base_url=args.url.rstrip("/"),
        qa_key=args.qa_key,
        verify_ssl=not args.no_verify,
        timeout=args.timeout,
        dump_on_fail=args.dump_on_fail,
    )

    start = time.monotonic()
    try:
        exit_code = runner.run(phases)
    except SystemExit as exc:
        exit_code = int(exc.code or 2)

    elapsed = time.monotonic() - start

    if args.json:
        exit_code = runner.report_json(elapsed)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
