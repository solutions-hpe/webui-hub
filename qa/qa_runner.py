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


@dataclass
class QARunner:
    base_url: str
    qa_key: str          # raw QA API key — exchanged for a JWT at startup
    tenant_id: str = ""  # populated from the token exchange response
    verify_ssl: bool = True
    timeout: float = 15.0
    results: list[TestResult] = field(default_factory=list)
    token: str = ""
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

    # ── Result helpers ────────────────────────────────────────────────────────

    def _ok(self, name: str, phase: str, detail: str = "") -> TestResult:
        r = TestResult(name=name, phase=phase, passed=True, detail=detail)
        self.results.append(r)
        return r

    def _fail(self, name: str, phase: str, detail: str = "") -> TestResult:
        r = TestResult(name=name, phase=phase, passed=False, detail=detail)
        self.results.append(r)
        return r

    def _skip(self, name: str, phase: str, reason: str = "") -> TestResult:
        r = TestResult(name=name, phase=phase, passed=True, skipped=True, detail=reason)
        self.results.append(r)
        return r

    def _warn(self, name: str, phase: str, detail: str = "") -> TestResult:
        r = TestResult(name=name, phase=phase, passed=True, warning=True, detail=detail)
        self.results.append(r)
        return r

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
        self._check("Command queue readable", "commands", r)

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
                        # Parse ISO 8601 timestamp
                        import datetime
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
        }

        selected = phases if phases else list(all_phases.keys())
        unknown = [p for p in selected if p not in all_phases]
        if unknown:
            print(f"Unknown phases: {unknown}. Valid: {list(all_phases.keys())}", file=sys.stderr)
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
