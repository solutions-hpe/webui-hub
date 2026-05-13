/**
 * shared.js — HPE Client-Sim shared UI library
 *
 * Pure render functions: data-in → HTML-out. No DOM mutation, no fetch, no globals.
 * Loaded by both webui-hub (served from /shared/shared.js) and webui-spoke
 * (copied to /static/shared.js by the installer at deploy time).
 *
 * Load this script BEFORE app.js in both hub and spoke index.html files.
 */

// ── Utility functions ────────────────────────────────────────────────────────

function escHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

/**
 * Returns a human-readable relative time string from an ISO 8601 timestamp.
 * e.g. "2m ago", "5h ago", "3d ago"
 */
function relativeTime(iso) {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diff = Math.max(0, Date.now() - then);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return fmtDate(iso);
}

/** Format a byte count into MB / GB / TB. */
function fmtSize(bytes) {
  const b = Number(bytes) || 0;
  if (b >= 1024 ** 4) return (b / 1024 ** 4).toFixed(1) + " TB";
  if (b >= 1024 ** 3) return (b / 1024 ** 3).toFixed(1) + " GB";
  if (b >= 1024 ** 2) return (b / 1024 ** 2).toFixed(0) + " MB";
  return b + " B";
}

/** Format a KB count (as returned by Proxmox node stats) into human-readable. */
function fmtSizeKB(kb) {
  return fmtSize(Number(kb) * 1024);
}

/**
 * Returns true if the ISO timestamp is within thresholdMs of now.
 * Default threshold: 2 minutes (matches spoke's 120-second heartbeat window).
 */
function isOnline(lastSeenIso, thresholdMs = 120_000) {
  if (!lastSeenIso) return false;
  const ts = new Date(lastSeenIso).getTime();
  return !Number.isNaN(ts) && Date.now() - ts < thresholdMs;
}

/** Renders a small coloured status dot span. */
function statusDot(online) {
  return `<span class="status-dot ${online ? "online" : "offline"}"></span>`;
}

// ── Client table ─────────────────────────────────────────────────────────────

/**
 * Renders client telemetry rows for the shared client table.
 * Columns: Status | Hostname | HW Type | Simulation | SSID | GW | VH | Errors
 * Returns an HTML string suitable for a <tbody>.
 */
function renderClientRows(clients = []) {
  if (!clients.length) {
    return '<tr><td colspan="8" class="empty-state">No client telemetry reported.</td></tr>';
  }
  return clients.map(client => {
    const online = client.online ?? isOnline(client.last_seen);
    const hostname = escHtml(client.hostname || "—");
    const hwType = client.hw_type ? `<span class="hw-type-badge">${escHtml(client.hw_type)}</span>` : "—";
    const sim = escHtml(client.simulation_id || "—");
    const ssid = escHtml(client.connected_ssid || "—");
    const gw = client.gateway_reachable
      ? '<span class="check-yes" title="Gateway reachable">✓</span>'
      : '<span class="check-no" title="Gateway unreachable">✗</span>';
    const vh = client.vh_connected
      ? '<span class="check-yes" title="VH connected">✓</span>'
      : '<span class="check-no" title="VH not connected">✗</span>';
    const errCount = Number(client.error_count || 0);
    const errCell = errCount > 0
      ? `<span class="client-error-count" title="${escHtml((client.recent_errors || []).join("\n"))}">${errCount}</span>`
      : "—";
    return `
      <tr>
        <td>${statusDot(online)}</td>
        <td>${hostname}</td>
        <td>${hwType}</td>
        <td>${sim}</td>
        <td>${ssid}</td>
        <td>${gw}</td>
        <td>${vh}</td>
        <td>${errCell}</td>
      </tr>`;
  }).join("");
}

// ── Proxmox / Server panel ───────────────────────────────────────────────────

/**
 * Renders a compact Proxmox node stats bar from the proxmox telemetry dict.
 * proxmox: { connected, node: { cpu_percent, mem_used_kb, mem_total_kb, storage[] },
 *            vm_count, running_count, agent_version, pve_version }
 */
function renderNodeStats(proxmox = {}) {
  if (!proxmox.connected) {
    return `<div class="node-stats-disconnected">
      <span class="badge badge-grey">⚠ Proxmox agent not connected</span>
    </div>`;
  }
  const node = proxmox.node || {};
  const cpu = node.cpu_percent != null ? `${Number(node.cpu_percent).toFixed(1)}%` : "—";
  const memUsed = node.mem_used_kb ? fmtSizeKB(node.mem_used_kb) : "—";
  const memTotal = node.mem_total_kb ? fmtSizeKB(node.mem_total_kb) : "—";
  const memPct = (node.mem_used_kb && node.mem_total_kb)
    ? Math.round((node.mem_used_kb / node.mem_total_kb) * 100) : null;
  const cpuClass = (node.cpu_percent || 0) > 80 ? "stat-pill-warn" : "stat-pill-ok";
  const memClass = (memPct || 0) > 80 ? "stat-pill-warn" : "stat-pill-ok";

  const storageHtml = (node.storage || []).map(s => {
    const used = fmtSizeKB(s.used || 0);
    const total = fmtSizeKB(s.total || 0);
    const pct = s.total ? Math.round(((s.used || 0) / s.total) * 100) : 0;
    const cls = pct > 85 ? "stat-pill-warn" : "stat-pill-ok";
    return `<span class="node-stat-pill ${cls}" title="${escHtml(s.storage || "")}">
      💾 ${escHtml(s.storage || "disk")} ${used}/${total} (${pct}%)
    </span>`;
  }).join("");

  const vmSummary = `${proxmox.running_count ?? 0} running / ${proxmox.vm_count ?? 0} total VMs`;
  const agentBadge = proxmox.agent_version
    ? `<span class="node-stat-pill stat-pill-ok" title="Proxmox agent version">🤖 agent v${escHtml(proxmox.agent_version)}</span>`
    : "";
  const pveBadge = proxmox.pve_version
    ? `<span class="node-stat-pill stat-pill-ok" title="PVE version">🖥 PVE ${escHtml(proxmox.pve_version)}</span>`
    : "";

  return `<div class="node-stats-bar">
    <span class="node-stat-pill ${cpuClass}">⚡ CPU ${cpu}</span>
    <span class="node-stat-pill ${memClass}">🧠 RAM ${memUsed}/${memTotal}${memPct != null ? ` (${memPct}%)` : ""}</span>
    ${storageHtml}
    <span class="node-stat-pill stat-pill-ok">🖥 ${vmSummary}</span>
    ${agentBadge}${pveBadge}
  </div>`;
}

/**
 * Renders a read-only VM table.
 * vms: [{ vmid, name, status, type }]
 * recloneVmid: optional current VM being recloned
 */
function renderVMTable(vms = [], recloneVmid = null) {
  if (!vms.length) {
    return '<p class="empty-state">No VMs reported.</p>';
  }
  const sorted = [...vms].sort((a, b) => {
    if (a.status === "running" && b.status !== "running") return -1;
    if (b.status === "running" && a.status !== "running") return 1;
    return Number(a.vmid) - Number(b.vmid);
  });
  const rows = sorted.map(vm => {
    const isRecloning = recloneVmid != null && Number(vm.vmid) === Number(recloneVmid);
    const statusIcon = vm.status === "running" ? "🟢" : vm.status === "paused" ? "🟡" : "⚫";
    const statusLabel = isRecloning
      ? '🔄 <span class="badge badge-yellow">recloning…</span>'
      : `${statusIcon} ${escHtml(vm.status || "unknown")}`;
    const typeLabel = vm.type === "lxc"
      ? '<span class="badge badge-blue">LXC</span>'
      : '<span class="badge badge-grey">VM</span>';
    return `<tr>
      <td>${escHtml(String(vm.vmid))}</td>
      <td>${escHtml(vm.name || "—")}</td>
      <td>${statusLabel}</td>
      <td>${typeLabel}</td>
    </tr>`;
  }).join("");
  return `<table class="data-table shared-vm-table">
    <thead><tr><th>VMID</th><th>Name</th><th>Status</th><th>Type</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

// ── Reclone panel ────────────────────────────────────────────────────────────

/**
 * Renders a compact reclone status panel.
 * reclone: { status, type, total, completed, failed, current_vm, phase, last_run, started_at }
 */
function renderReclonePanel(reclone = {}) {
  const status = reclone.status || "idle";
  const badgeClass = status === "running" ? "badge-blue"
    : status === "completed" ? "badge-green"
    : status === "failed"    ? "badge-red"
    : "badge-grey";
  const phaseMap = { stopping: "Stopping", cloning: "Cloning", starting: "Starting" };
  const phaseLabel = phaseMap[reclone.phase] || "";
  const badgeLabel = (status === "running" && reclone.current_vm)
    ? `${phaseLabel || "Recloning"} VM ${reclone.current_vm}`
    : status === "idle" ? "Idle"
    : status.charAt(0).toUpperCase() + status.slice(1);

  const total = Number(reclone.total || 0);
  const done = Number(reclone.completed || 0) + Number(reclone.failed || 0);
  const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
  const showProgress = status === "running" || done > 0;

  const typeMap = { scheduled: "Scheduled", manual: "Manual", "auto-recovery": "Auto-Recovery" };
  const typeLabel = typeMap[reclone.type] || "";
  const typeBadge = reclone.type && status !== "idle"
    ? `<span class="badge ${reclone.type === "auto-recovery" ? "badge-yellow" : "badge-blue"}">${typeLabel}</span>`
    : "";

  const progressHtml = showProgress ? `
    <div class="reclone-progress-wrap">
      <div class="reclone-progress-bar-outer">
        <div class="reclone-progress-bar-inner" style="width:${pct}%"></div>
      </div>
      <span class="reclone-progress-label">${done} / ${total} VMs (${pct}%)</span>
    </div>` : "";

  const lastRunHtml = reclone.last_run
    ? `<span class="muted-label">Last run: ${relativeTime(reclone.last_run)}</span>`
    : "";

  // ETA estimate
  let etaHtml = "";
  if (status === "running" && done > 0 && total > done && reclone.started_at) {
    const elapsed = (Date.now() - new Date(reclone.started_at).getTime()) / 1000;
    const avgSec = elapsed / done;
    const remaining = (total - done) * avgSec;
    etaHtml = `<span class="muted-label">~${Math.ceil(remaining / 60)} min remaining</span>`;
  }

  return `<div class="reclone-compact-panel">
    <div class="reclone-compact-header">
      <span class="badge ${badgeClass}">${badgeLabel}</span>
      ${typeBadge}
      ${etaHtml}
      ${lastRunHtml}
    </div>
    ${progressHtml}
  </div>`;
}

// ── Simulation distribution ───────────────────────────────────────────────────

/**
 * Renders a simulation breakdown table from the clients array.
 * Groups clients by simulation_id and shows online/total counts.
 */
function renderSimulationDistribution(clients = []) {
  if (!clients.length) {
    return '<p class="empty-state">No clients reported.</p>';
  }
  const groups = {};
  for (const c of clients) {
    const sim = c.simulation_id || "(none)";
    if (!groups[sim]) groups[sim] = { total: 0, online: 0, errors: 0 };
    groups[sim].total++;
    if (c.online ?? isOnline(c.last_seen)) groups[sim].online++;
    groups[sim].errors += Number(c.error_count || 0);
  }
  const rows = Object.entries(groups)
    .sort((a, b) => b[1].total - a[1].total)
    .map(([sim, g]) => {
      const errCell = g.errors > 0
        ? `<span class="client-error-count">${g.errors}</span>`
        : "—";
      return `<tr>
        <td>${escHtml(sim)}</td>
        <td>${g.online} / ${g.total}</td>
        <td>${errCell}</td>
      </tr>`;
    }).join("");
  return `<table class="data-table shared-sim-dist-table">
    <thead><tr><th>Simulation</th><th>Online / Total</th><th>Errors</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

// ── Kill switch badge ─────────────────────────────────────────────────────────

/** Renders a kill switch state badge: "ON" (red) or "OFF" (green). */
function renderKillSwitchBadge(state) {
  const on = state === "on";
  return `<span class="badge ${on ? "badge-red" : "badge-green"}">
    ⚡ Kill Switch ${on ? "ON" : "OFF"}
  </span>`;
}

// ── Relay status ──────────────────────────────────────────────────────────────

/**
 * Renders a relay/hub connection status summary.
 * relay: { enabled, connected, registration_status, last_sync, error }
 */
function renderRelayStatus(relay = {}) {
  if (!relay.enabled) {
    return '<span class="badge badge-grey">Relay disabled</span>';
  }
  const regStatus = relay.registration_status || "unregistered";
  const badgeClass = relay.connected ? "badge-green"
    : regStatus === "pending" ? "badge-yellow"
    : "badge-grey";
  const label = relay.connected ? "Hub Connected"
    : regStatus === "pending" ? "Pending Approval"
    : regStatus === "approved" ? "Disconnected"
    : "Unregistered";
  const lastSync = relay.last_sync
    ? `<span class="muted-label">Synced ${relativeTime(relay.last_sync)}</span>`
    : "";
  const errorHtml = relay.error
    ? `<span class="relay-error-label" title="${escHtml(relay.error)}">⚠ ${escHtml(relay.error.substring(0, 60))}${relay.error.length > 60 ? "…" : ""}</span>`
    : "";
  return `<span class="badge ${badgeClass}">🔗 ${label}</span> ${lastSync} ${errorHtml}`;
}
