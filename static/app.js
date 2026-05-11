"use strict";

// Keep the lightweight pre-commit balance check aligned with this bundle.
void /\)\}/;

let authToken = localStorage.getItem("hub_token") || null;
let currentUser = null;
let currentTenantId = null;
let tenants = [];
let spokeCache = {};
let activeSpokeModal = null;
let ws = null;
let wsReconnectTimer = null;
let activeTab = "dashboard";
let tenantContextActive = false;
let dashboardTenantRows = [];
let autoRefreshTimer = null;
let autoRefreshCountdownTimer = null;
let autoRefreshSecondsLeft = 10;

const PROCESSING_FEATURES = ["aruba_polling", "teams_webhook", "email", "heartbeat", "gkill", "schedules", "repo_sync"];
const spokeUiState = { expandedByTenant: {}, search: "" };
const renderTokens = {};
const scheduledReloads = {};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

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

function showToast(message, level = "ok") {
  const container = $("#toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  const cls = level === "ok" ? "success" : level === "warn" ? "error" : "error";
  toast.className = `settings-message ${cls}`;
  toast.textContent = message;
  toast.style.cssText = "min-width:240px;max-width:420px;box-shadow:0 4px 16px rgba(0,0,0,0.15);cursor:pointer;";
  toast.addEventListener("click", () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
}

function isOnline(lastSeenIso) {
  if (!lastSeenIso) return false;
  const ts = new Date(lastSeenIso).getTime();
  return !Number.isNaN(ts) && Date.now() - ts < 120000;
}

function statusDot(online) {
  return `<span class="status-dot ${online ? "online" : "offline"}"></span>`;
}

function updateGkillBadge(value) {
  const badge = $("#gkill-badge");
  if (!badge) return;
  const on = ["on", "true", "1", "enabled"].includes(String(value || "").toLowerCase());
  badge.classList.toggle("hidden", !on);
  badge.textContent = on ? "⚠ GKILL ON" : "GKILL OFF";
}

function updateApiStatus(online, text) {
  const dot = $("#api-dot");
  const label = $("#api-text");
  if (dot) dot.className = `status-dot ${online ? "online" : "offline"}`;
  if (label) label.textContent = text;
}

function setFormMessage(id, message, ok = true) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = message || "";
  el.className = `form-msg ${message ? (ok ? "msg-ok" : "msg-error") : ""}`.trim();
}

function tenantName(tenantId) {
  const tenant = tenants.find(item => item.id === tenantId);
  return tenant ? tenant.name : tenantId;
}

function currentRoleForTenant(tenantId = currentTenantId) {
  if (!currentUser) return "";
  if (currentUser.is_superadmin) return "superadmin";
  return currentUser.tenant_roles.find(role => role.tenant_id === tenantId)?.role || "";
}

function canManageTenant(tenantId = currentTenantId) {
  if (!currentUser || !tenantId) return false;
  return currentUser.is_superadmin || currentRoleForTenant(tenantId) === "admin";
}

function scheduleReload(key, callback, delay = 250) {
  if (scheduledReloads[key]) clearTimeout(scheduledReloads[key]);
  scheduledReloads[key] = window.setTimeout(() => {
    scheduledReloads[key] = null;
    callback();
  }, delay);
}

async function apiFetch(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  const init = { ...options, headers };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  if (init.body && !(init.body instanceof FormData) && typeof init.body !== "string") {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  const response = await fetch(url, init).catch(() => null);
  if (!response) {
    updateApiStatus(false, "Disconnected");
    return null;
  }
  updateApiStatus(true, "Connected");
  if (response.status === 401 && authToken) {
    logout(false);
    return null;
  }
  return response;
}

async function readJson(response) {
  if (!response) return null;
  return response.json().catch(() => null);
}

function renderInBatches(key, container, items, renderItem, batchSize = 40) {
  renderTokens[key] = (renderTokens[key] || 0) + 1;
  const token = renderTokens[key];
  container.innerHTML = "";
  let index = 0;
  function draw() {
    if (renderTokens[key] !== token) return;
    const fragment = document.createDocumentFragment();
    for (let count = 0; count < batchSize && index < items.length; count += 1, index += 1) {
      fragment.appendChild(renderItem(items[index], index));
    }
    container.appendChild(fragment);
    if (index < items.length) window.requestAnimationFrame(draw);
  }
  window.requestAnimationFrame(draw);
}

async function pingApi() {
  const res = await fetch("/api/health").catch(() => null);
  const ok = Boolean(res && res.ok);
  updateApiStatus(ok, ok ? "Connected" : "Disconnected");
  if (ok) {
    const data = await res.json().catch(() => null);
    const footerVer = $("#footer-version");
    if (footerVer && data?.version) {
      footerVer.textContent = `v${data.version}`;
      footerVer.title = `Branch: ${data.branch || "?"} | SHA: ${data.sha || "?"}`;
    }
  }
}

function getExpandedSet(tenantId = currentTenantId) {
  if (!tenantId) return new Set();
  if (!spokeUiState.expandedByTenant[tenantId]) spokeUiState.expandedByTenant[tenantId] = new Set();
  return spokeUiState.expandedByTenant[tenantId];
}

function syncRoleBadge() {
  const badge = $("#topbar-role-badge");
  if (!badge || !currentUser) return;
  badge.textContent = currentUser.is_superadmin ? "SUPERADMIN" : (currentRoleForTenant() || "user").toUpperCase();
}

function buildTenantSelector() {}
function clearDynamicTenantTabs() {}
function buildSuperadminTenantTabs() {}

function syncTenantContextChrome() {
  const active = Boolean(currentUser && authToken && tenantContextActive && currentTenantId);
  $("#hub-admin-nav")?.classList.toggle("hidden", active);
  $("#tenant-context-nav")?.classList.toggle("hidden", !active);
  $("#hub-admin-topbar-nav")?.classList.toggle("hidden", !active);
  $("#tenant-context-indicator")?.classList.toggle("hidden", !active);
  $("#tenant-context-name") && ($("#tenant-context-name").textContent = tenantName(currentTenantId) || currentTenantId || "—");
}

function syncHubPermissionUI() {
  const canManageCurrent = Boolean(currentUser && currentTenantId && (canManageTenant() || currentUser.is_superadmin));
  [
    '#hub-admin-nav .tab[data-tab="settings"]',
    '#hub-admin-topbar-nav [data-admin-tab="settings"]',
    '#tenant-context-nav .tab[data-tab="settings"]',
  ].forEach(selector => {
    $$(selector).forEach(el => el.classList.toggle("hidden", !canManageCurrent));
  });
  $("#dashboard-add-tenant-btn")?.classList.toggle("hidden", !currentUser?.is_superadmin);
}

function applyAuthUI() {
  const loggedIn = Boolean(currentUser && authToken);
  $("#login-btn")?.classList.toggle("hidden", loggedIn);
  $("#topbar-user")?.classList.toggle("hidden", !loggedIn);
  $("#topbar-username") && ($("#topbar-username").textContent = currentUser?.username || "");
  $$(".auth-tab").forEach(tab => tab.classList.toggle("hidden", !loggedIn));
  $$(".superadmin-tab").forEach(tab => tab.classList.toggle("hidden", !(loggedIn && currentUser?.is_superadmin)));
  if (!loggedIn) {
    currentTenantId = null;
    tenantContextActive = false;
    tenants = [];
    spokeCache = {};
    dashboardTenantRows = [];
    syncTenantContextChrome();
    if (activeTab !== "dashboard") showTab("dashboard");
    return;
  }
  syncRoleBadge();
  syncTenantContextChrome();
  syncHubPermissionUI();
}

async function loadUserContext() {
  if (!authToken) {
    currentUser = null;
    applyAuthUI();
    return;
  }
  const meRes = await apiFetch("/api/auth/me");
  if (!meRes || !meRes.ok) {
    logout(false);
    return;
  }
  currentUser = await meRes.json();
  if (currentUser.is_superadmin) {
    const tenantsRes = await apiFetch("/api/superadmin/tenants");
    tenants = tenantsRes && tenantsRes.ok ? (await tenantsRes.json()).map(item => ({ id: item.id, name: item.name || item.id })) : [];
  } else {
    tenants = (currentUser.tenant_roles || []).map(role => ({ id: role.tenant_id, name: role.tenant_id }));
  }
  if (tenants.length && !tenants.some(tenant => tenant.id === currentTenantId)) {
    currentTenantId = tenants[0].id;
  }
  applyAuthUI();
  syncHubPermissionUI();
  populateCommandSpokeSelect();
}

function openLoginModal() {
  $("#login-modal")?.classList.remove("hidden");
  $("#login-error") && ($("#login-error").textContent = "");
  $("#login-username")?.focus();
}

function closeLoginModal() {
  $("#login-modal")?.classList.add("hidden");
  setFormMessage("login-error", "", false);
}

async function submitLogin() {
  const username = $("#login-username")?.value.trim();
  const password = $("#login-password")?.value || "";
  if (!username || !password) {
    setFormMessage("login-error", "Enter username and password.", false);
    return;
  }
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  }).catch(() => null);
  if (!res || !res.ok) {
    const data = res ? await res.json().catch(() => null) : null;
    const detail = data?.detail;
    setFormMessage("login-error", detail?.message || detail || "Invalid credentials.", false);
    return;
  }
  const payload = await res.json();
  authToken = payload.access_token;
  localStorage.setItem("hub_token", authToken);
  closeLoginModal();
  await loadUserContext();
  connectWebSocket();
  await refreshCurrentView(true);
  showToast("Signed in successfully.", "ok");
}

function logout(showMessage = true) {
  authToken = null;
  currentUser = null;
  currentTenantId = null;
  tenantContextActive = false;
  tenants = [];
  spokeCache = {};
  dashboardTenantRows = [];
  activeSpokeModal = null;
  localStorage.removeItem("hub_token");
  applyAuthUI();
  closeSpokeModal();
  if (showMessage) showToast("Signed out.", "ok");
}

async function setCurrentTenant(tenantId, reload = true) {
  currentTenantId = tenantId;
  syncRoleBadge();
  syncTenantContextChrome();
  syncHubPermissionUI();
  populateCommandSpokeSelect();
  if (reload && ["spokes", "commands", "settings"].includes(activeTab)) await refreshCurrentView(true);
}

function showTab(tabId, opts = {}) {
  if (["spokes", "commands", "settings", "superadmin"].includes(tabId) && !currentUser) {
    openLoginModal();
    return;
  }
  if (opts.source === "admin") tenantContextActive = false;
  if (opts.source === "tenant") tenantContextActive = true;
  activeTab = tabId;
  $$(".tab-content").forEach(panel => panel.classList.add("hidden"));
  const panel = document.getElementById(`tab-${tabId}`);
  if (panel) panel.classList.remove("hidden");
  $$("#tab-nav .tab").forEach(button => button.classList.remove("active"));
  if (opts.button) {
    opts.button.classList.add("active");
  } else {
    const selector = tenantContextActive ? `#tenant-context-nav .tab[data-tab="${tabId}"]` : `#hub-admin-nav .tab[data-tab="${tabId}"]`;
    $(selector)?.classList.add("active");
  }
  syncTenantContextChrome();
  syncHubPermissionUI();
  refreshCurrentView();
}

async function refreshCurrentView(force = false) {
  if (activeTab === "dashboard") {
    await loadDashboard();
  } else if (activeTab === "spokes") {
    await loadSpokes(force);
  } else if (activeTab === "commands") {
    await loadCommands();
  } else if (activeTab === "settings") {
    await loadSettings();
  } else if (activeTab === "superadmin") {
    await loadSuperadmin();
  }
}

function getTenantSpokes() {
  return currentTenantId ? (spokeCache[currentTenantId] || []) : [];
}

function spokeLabel(count) {
  return `${count} ${count === 1 ? "spoke" : "spokes"}`;
}

function spokePrimaryLabel(spoke) {
  return String(spoke?.spoke_name || spoke?.hostname || spoke?.id || "—");
}

function spokeSecondaryLabel(spoke, fallback = "—") {
  const primary = spokePrimaryLabel(spoke);
  const parts = [];
  const hostname = String(spoke?.hostname || "").trim();
  const label = String(spoke?.label || "").trim();
  const workspace = String(spoke?.workspace_id || spoke?.tenant_id || "").trim();
  if (hostname && hostname !== primary) parts.push(hostname);
  if (label && label !== primary && label !== hostname) parts.push(label);
  if (!parts.length && workspace && workspace !== primary) parts.push(workspace);
  return parts.join(" · ") || fallback;
}

function spokeCommandLabel(spoke) {
  const primary = spokePrimaryLabel(spoke);
  const hostname = String(spoke?.hostname || "").trim();
  return hostname && hostname !== primary ? `${primary} (${hostname})` : primary;
}

function spokeSearchText(spoke) {
  return [
    spokePrimaryLabel(spoke),
    String(spoke?.hostname || ""),
    String(spoke?.label || ""),
    String(spoke?.id || ""),
  ].join(" ").toLowerCase();
}

function updateSpokeStatPills(spokes) {
  const approved = spokes.filter(spoke => spoke.status === "approved");
  const onlineCount = approved.filter(spoke => isOnline(spoke.last_seen)).length;
  const clientCount = approved.reduce((sum, spoke) => sum + ((spoke.telemetry?.clients || []).length), 0);
  $("#spokes-count-pill") && ($("#spokes-count-pill").textContent = spokeLabel(approved.length));
  $("#spokes-online-pill") && ($("#spokes-online-pill").textContent = `${onlineCount} online`);
  $("#spokes-clients-pill") && ($("#spokes-clients-pill").textContent = `${clientCount} clients`);
}

function summarizeTenantSpokes(spokes = []) {
  const approved = spokes.filter(spoke => spoke.status === "approved");
  const onlineCount = approved.filter(spoke => isOnline(spoke.last_seen)).length;
  const lastSeenTimes = approved.map(spoke => new Date(spoke.last_seen).getTime()).filter(Number.isFinite);
  return {
    approvedCount: approved.length,
    onlineCount,
    offlineCount: Math.max(0, approved.length - onlineCount),
    pendingCount: Math.max(0, spokes.length - approved.length),
    clientCount: approved.reduce((sum, spoke) => sum + ((spoke.telemetry?.clients || []).length), 0),
    lastSync: lastSeenTimes.length ? new Date(Math.max(...lastSeenTimes)).toISOString() : null,
  };
}

async function ensureSpokesForTenant(tenantId, force = false) {
  if (!tenantId) return [];
  if (!force && spokeCache[tenantId]) return spokeCache[tenantId];
  const res = await apiFetch(`/api/${encodeURIComponent(tenantId)}/spokes`);
  if (!res || !res.ok) return spokeCache[tenantId] || [];
  const spokes = await res.json();
  spokeCache[tenantId] = spokes;
  return spokes;
}

function summarizeTenantAlerts(summary) {
  if (summary.pendingCount > 0) return { tone: "alert", text: `${summary.pendingCount} pending ${summary.pendingCount === 1 ? "spoke" : "spokes"}` };
  if (summary.offlineCount > 0) return { tone: "alert", text: `${summary.offlineCount} offline ${summary.offlineCount === 1 ? "spoke" : "spokes"}` };
  return { tone: "ok", text: "OK" };
}

function renderTenantRow(rowData) {
  const { id, name, summary, alert } = rowData;
  const row = document.createElement("div");
  row.className = "tenant-list-row";
  row.innerHTML = `
    <button class="tenant-list-main" data-enter-tenant="${escHtml(id)}" type="button">
      <span class="tenant-list-name">${escHtml(name || id)}</span>
      <span class="tenant-list-id">Tenant ID: ${escHtml(id)}</span>
    </button>
    <div class="tenant-list-count">
      <span class="tenant-list-count-label">Spokes</span>
      <strong class="tenant-list-count-value">${summary.approvedCount}</strong>
    </div>
    <div class="tenant-list-count">
      <span class="tenant-list-count-label">Clients</span>
      <strong class="tenant-list-count-value">${summary.clientCount}</strong>
    </div>
    <div class="tenant-list-count tenant-list-alerts">
      <span class="tenant-list-count-label">Alerts</span>
      <span class="tenant-alert-pill ${alert.tone}">${escHtml(alert.text)}</span>
    </div>
    <button class="tenant-select-btn" data-enter-tenant="${escHtml(id)}" type="button" aria-label="Select ${escHtml(name || id)}">
      <span>Select</span>
      <span class="tenant-list-chevron" aria-hidden="true">›</span>
    </button>
  `;
  return row;
}

function renderTenantDashboardEmptyState() {
  return currentUser?.is_superadmin
    ? 'No tenants yet. Create your first tenant to get started.<div class="tenant-empty-action"><button class="btn btn-primary btn-small" data-add-tenant type="button">Add Tenant</button></div>'
    : 'No tenants are available yet. Contact a hub administrator to add one.';
}

async function loadDashboard(force = false) {
  const grid = $("#dashboard-grid");
  const empty = $("#dashboard-empty");
  if (currentUser) {
    dashboardTenantRows = [];
    $("#dash-tenants-pill") && ($("#dash-tenants-pill").textContent = `${tenants.length} tenants`);
    $("#dashboard-add-tenant-btn")?.classList.toggle("hidden", !currentUser?.is_superadmin);
    if (!grid || !empty) return;
    grid.classList.remove("spoke-grid");
    grid.classList.add("tenant-list");
    if (!tenants.length) {
      grid.innerHTML = "";
      $("#dash-spokes-pill") && ($("#dash-spokes-pill").textContent = '0 spokes');
      $("#dash-clients-pill") && ($("#dash-clients-pill").textContent = '0 clients');
      $("#dash-online-pill") && ($("#dash-online-pill").textContent = '0 alerts');
      empty.innerHTML = renderTenantDashboardEmptyState();
      empty.classList.remove("hidden");
      return;
    }
    const rows = await Promise.all(tenants.map(async tenant => {
      const spokes = await ensureSpokesForTenant(tenant.id, force);
      const summary = summarizeTenantSpokes(spokes || []);
      return { id: tenant.id, name: tenant.name || tenant.id, summary, alert: summarizeTenantAlerts(summary) };
    }));
    rows.sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id), undefined, { numeric: true, sensitivity: "base" }));
    dashboardTenantRows = rows;
    const totalSpokes = rows.reduce((sum, row) => sum + row.summary.approvedCount, 0);
    const totalClients = rows.reduce((sum, row) => sum + row.summary.clientCount, 0);
    const totalAlerts = rows.filter(row => row.alert.tone === "alert").length;
    $("#dash-spokes-pill") && ($("#dash-spokes-pill").textContent = `${totalSpokes} spokes`);
    $("#dash-clients-pill") && ($("#dash-clients-pill").textContent = `${totalClients} clients`);
    $("#dash-online-pill") && ($("#dash-online-pill").textContent = totalAlerts ? `${totalAlerts} tenants need attention` : 'All tenants OK');
    empty.classList.toggle("hidden", rows.length > 0);
    empty.innerHTML = rows.length ? "" : renderTenantDashboardEmptyState();
    renderInBatches("dashboard", grid, rows, renderTenantRow, 40);
    return;
  }

  grid?.classList.add("spoke-grid");
  grid?.classList.remove("tenant-list");
  const res = await fetch("/api/sites").catch(() => null);
  if (!res || !res.ok) return;
  const sites = (await res.json()).filter(site => site.status === "approved");
  $("#dash-tenants-pill") && ($("#dash-tenants-pill").textContent = 'Public dashboard');
  const onlineCount = sites.filter(site => isOnline(site.last_seen)).length;
  const clientCount = sites.reduce((sum, site) => sum + ((site.telemetry?.clients || []).length), 0);
  $("#dash-spokes-pill") && ($("#dash-spokes-pill").textContent = spokeLabel(sites.length));
  $("#dash-clients-pill") && ($("#dash-clients-pill").textContent = `${clientCount} clients`);
  $("#dash-online-pill") && ($("#dash-online-pill").textContent = `${onlineCount} online`);
  empty?.classList.toggle("hidden", sites.length > 0);
  if (!grid) return;
  renderInBatches("dashboard", grid, sites, site => {
    const online = isOnline(site.last_seen);
    const clients = site.telemetry?.clients || [];
    const card = document.createElement("article");
    card.className = "spoke-card compact-card";
    card.dataset.tenantId = site.workspace_id || site.tenant_id || "";
    card.dataset.spokeId = site.id;
    card.innerHTML = `
      <div class="spoke-card-header-row">
        <div class="spoke-card-title-wrap">
          <div class="spoke-card-title">${escHtml(spokePrimaryLabel(site))}</div>
          <div class="spoke-card-subtitle">${escHtml(spokeSecondaryLabel(site, site.workspace_id || "—"))}</div>
        </div>
        <div class="spoke-card-status" data-online-state>${statusDot(online)}</div>
      </div>
      <div class="spoke-card-meta">
        <span class="stat-pill">${clients.length} clients</span>
        <span class="stat-pill">${online ? "Online" : "Offline"}</span>
      </div>
      <div class="spoke-card-footer">Last seen ${escHtml(relativeTime(site.last_seen))}</div>
    `;
    return card;
  }, 60);
}

async function ensureSpokes(force = false) {
  if (!currentTenantId) return [];
  const spokes = await ensureSpokesForTenant(currentTenantId, force);
  populateCommandSpokeSelect();
  return spokes;
}

function renderClientRows(clients = []) {
  if (!clients.length) {
    return '<tr><td colspan="5" class="empty-state">No client telemetry reported.</td></tr>';
  }
  return clients.map(client => {
    const online = isOnline(client.last_seen);
    const clientId = client.client_id || client.id || client.hostname || "—";
    return `
      <tr>
        <td>${escHtml(clientId)}</td>
        <td>${escHtml(client.hostname || client.client_id || client.id || "—")}</td>
        <td><span class="site-status-pill ${online ? "online" : "offline"}">${online ? "Online" : "Offline"}</span></td>
        <td>${escHtml(relativeTime(client.last_seen))}</td>
        <td>${escHtml(client.ip_address || client.ip || "—")}</td>
      </tr>
    `;
  }).join("");
}

function renderSpokeBody(section, spoke) {
  const body = $(".spoke-section-body", section);
  if (!body) return;
  const clients = spoke.telemetry?.clients || [];
  body.innerHTML = `
    <div class="spoke-section-summary">
      <span class="stat-pill">Workspace ${escHtml(tenantName(spoke.tenant_id))}</span>
      <span class="stat-pill">${clients.length} clients</span>
      <span class="stat-pill">Seen ${escHtml(relativeTime(spoke.last_seen))}</span>
    </div>
    <div class="spoke-action-bar">
      <button class="btn btn-secondary btn-small" data-action="detail" type="button">Open Detail</button>
      <button class="btn btn-secondary btn-small" data-action="audit" type="button">View Audit Log</button>
      <button class="btn btn-secondary btn-small" data-action="mode" type="button">Processing Mode</button>
      <select class="form-input form-input-sm quick-command-select">
        <option value="kill_switch">Kill Switch</option>
        <option value="restart_sim">Restart Simulation</option>
        <option value="reclone">Reclone</option>
        <option value="reboot">Reboot</option>
        <option value="repo_sync">Repo Sync</option>
        <option value="update_now">Update Now</option>
      </select>
      <button class="btn btn-primary btn-small" data-action="send" type="button">Send Command</button>
    </div>
    <table class="data-table spoke-client-table">
      <thead><tr><th>Client ID</th><th>Hostname</th><th>Status</th><th>Last Seen</th><th>IP</th></tr></thead>
      <tbody>${renderClientRows(clients)}</tbody>
    </table>
  `;
  const quickSelect = $(".quick-command-select", body);
  if (!canManageTenant(spoke.tenant_id)) {
    const modeButton = $('[data-action="mode"]', body);
    if (modeButton) modeButton.disabled = true;
  }
  body.addEventListener("click", async event => {
    const action = event.target.closest("[data-action]")?.dataset.action;
    if (!action) return;
    if (action === "detail") openSpokeModal(spoke, spoke.tenant_id, "spoke-clients");
    if (action === "audit") openSpokeModal(spoke, spoke.tenant_id, "spoke-audit");
    if (action === "mode") openSpokeModal(spoke, spoke.tenant_id, "spoke-mode");
    if (action === "send") await sendCommandToSpoke(spoke.tenant_id, spoke.id, quickSelect?.value || "kill_switch");
  }, { once: true });
}

function createSpokeSection(spoke) {
  const expanded = getExpandedSet().has(spoke.id);
  const online = isOnline(spoke.last_seen);
  const clients = spoke.telemetry?.clients || [];
  const section = document.createElement("section");
  section.className = "spoke-section";
  section.dataset.spokeId = spoke.id;
  section.dataset.tenantId = spoke.tenant_id;
  section.innerHTML = `
    <div class="spoke-section-header">
      <span class="spoke-toggle ${expanded ? "open" : ""}">▶</span>
      ${statusDot(online)}
      <span class="spoke-hostname">${escHtml(spokePrimaryLabel(spoke))}</span>
      <span class="spoke-label-inline">${escHtml(spokeSecondaryLabel(spoke))}</span>
      <span class="spoke-meta">${clients.length} clients · ${escHtml(relativeTime(spoke.last_seen))}</span>
    </div>
    <div class="spoke-section-body ${expanded ? "expanded" : ""}"></div>
  `;
  $(".spoke-section-header", section)?.addEventListener("click", event => {
    if (event.target.closest("button,select,input,a")) return;
    toggleSpokeSection(section, spoke);
  });
  if (expanded) {
    renderSpokeBody(section, spoke);
    $(".spoke-section-body", section).dataset.rendered = "1";
  }
  return section;
}

function toggleSpokeSection(section, spoke) {
  const expandedSet = getExpandedSet();
  const body = $(".spoke-section-body", section);
  const toggle = $(".spoke-toggle", section);
  const opening = !body.classList.contains("expanded");
  body.classList.toggle("expanded", opening);
  toggle?.classList.toggle("open", opening);
  if (opening) {
    expandedSet.add(spoke.id);
    if (!body.dataset.rendered) {
      renderSpokeBody(section, spoke);
      body.dataset.rendered = "1";
    }
  } else {
    expandedSet.delete(spoke.id);
  }
}

async function loadSpokes(force = false) {
  const spokes = await ensureSpokes(force);
  updateSpokeStatPills(spokes);
  const search = spokeUiState.search.trim().toLowerCase();
  const filtered = spokes.filter(spoke => spoke.status === "approved" && (!search || spokeSearchText(spoke).includes(search)));
  const list = $("#spokes-list");
  const empty = $("#spokes-empty");
  empty?.classList.toggle("hidden", filtered.length > 0);
  if (!list) return;
  if (!filtered.length) {
    list.innerHTML = "";
    return;
  }
  const group = document.createElement("section");
  group.className = "workspace-group setup-card";
  group.innerHTML = `<div class="workspace-header"><h2>${escHtml(tenantName(currentTenantId))}</h2><p>Workspace: ${escHtml(currentTenantId)}</p></div><div class="workspace-body"></div>`;
  list.innerHTML = "";
  list.appendChild(group);
  renderInBatches("spokes", $(".workspace-body", group), filtered, spoke => createSpokeSection(spoke), 30);
}

function populateCommandSpokeSelect() {
  const select = $("#cmd-spoke");
  if (!select) return;
  const spokes = getTenantSpokes().filter(spoke => spoke.status === "approved");
  select.innerHTML = spokes.map(spoke => `<option value="${escHtml(spoke.id)}">${escHtml(spokeCommandLabel(spoke))}</option>`).join("");
}

async function sendCommandToSpoke(tenantId, spokeId, type) {
  const response = await apiFetch("/api/commands", {
    method: "POST",
    body: { tenant_id: tenantId, island_id: spokeId, type, target: "spoke", payload: {} },
  });
  if (!response || !response.ok) {
    const err = await readJson(response);
    showToast(err?.detail || `Failed to send ${type}.`, "err");
    return false;
  }
  showToast(`${type} queued for ${spokeId}.`, "ok");
  if (activeTab === "commands") loadCommands();
  if (activeSpokeModal?.spoke?.id === spokeId) loadSpokeCommands();
  return true;
}

async function loadCommands() {
  if (!currentTenantId) return;
  await ensureSpokes();
  populateCommandSpokeSelect();
  const res = await apiFetch(`/api/${encodeURIComponent(currentTenantId)}/commands`);
  if (!res || !res.ok) return;
  const commands = await res.json();
  const queued = commands.filter(command => command.status === "queued").length;
  $("#commands-count-pill") && ($("#commands-count-pill").textContent = `${queued} queued`);
  const tbody = $("#commands-tbody");
  if (!tbody) return;
  if (!commands.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No commands queued.</td></tr>';
    return;
  }
  tbody.innerHTML = commands.map(command => {
    const spoke = getTenantSpokes().find(item => item.id === command.spoke_id);
    return `
      <tr>
        <td>${escHtml(spoke ? spokeCommandLabel(spoke) : command.spoke_id)}</td>
        <td>${escHtml(command.type)}</td>
        <td><span class="badge cmd-status-${escHtml(command.status)}">${escHtml(command.status)}</span></td>
        <td>${escHtml(fmtDate(command.created_at))}</td>
        <td>${escHtml(fmtDate(command.expires_at))}</td>
      </tr>
    `;
  }).join("");
}

async function sendCommandFromForm() {
  const spokeId = $("#cmd-spoke")?.value;
  const type = $("#cmd-type")?.value || "kill_switch";
  if (!currentTenantId || !spokeId) {
    setFormMessage("cmd-msg", "Select a spoke first.", false);
    return;
  }
  const ok = await sendCommandToSpoke(currentTenantId, spokeId, type);
  setFormMessage("cmd-msg", ok ? "Command queued." : "Failed to queue command.", ok);
  if (ok) loadCommands();
}

function getSpokeFromCache(tenantId, spokeId) {
  return (spokeCache[tenantId] || []).find(spoke => spoke.id === spokeId) || null;
}

function renderSpokeClientsTab() {
  const spoke = getSpokeFromCache(activeSpokeModal?.tenant_id, activeSpokeModal?.spoke?.id) || activeSpokeModal?.spoke;
  if (!spoke) return;
  activeSpokeModal.spoke = spoke;
  const tbody = $("#spoke-clients-tbody");
  if (!tbody) return;
  tbody.innerHTML = renderClientRows(spoke.telemetry?.clients || []);
}

async function loadSpokeCommands() {
  if (!activeSpokeModal) return;
  const { tenant_id: tenantId, spoke } = activeSpokeModal;
  const res = await apiFetch(`/api/${encodeURIComponent(tenantId)}/commands?island_id=${encodeURIComponent(spoke.id)}`);
  if (!res || !res.ok) return;
  const commands = await res.json();
  const tbody = $("#spoke-cmds-tbody");
  if (!tbody) return;
  const items = commands.slice(0, 20);
  tbody.innerHTML = items.length ? items.map(command => `
    <tr>
      <td>${escHtml(command.type)}</td>
      <td><span class="badge cmd-status-${escHtml(command.status)}">${escHtml(command.status)}</span></td>
      <td>${escHtml(fmtDate(command.created_at))}</td>
      <td>${escHtml(fmtDate(command.expires_at))}</td>
    </tr>`).join("") : '<tr><td colspan="4" class="empty-state">No commands for this spoke.</td></tr>';
}

async function loadSpokeAudit() {
  if (!activeSpokeModal) return;
  const { tenant_id: tenantId, spoke } = activeSpokeModal;
  const res = await apiFetch(`/api/${encodeURIComponent(tenantId)}/spokes/${encodeURIComponent(spoke.id)}/audit`);
  if (!res || !res.ok) return;
  const audit = (await res.json()).slice(-20).reverse();
  const tbody = $("#spoke-audit-tbody");
  if (!tbody) return;
  tbody.innerHTML = audit.length ? audit.map(entry => `
    <tr>
      <td>${escHtml(fmtDate(entry.timestamp))}</td>
      <td>${escHtml(entry.task_type)}</td>
      <td>${escHtml(entry.execution_mode)}</td>
      <td>${escHtml(entry.status)}</td>
      <td>${escHtml(entry.detail || "—")}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty-state">No audit entries.</td></tr>';
}

async function loadSpokeProcessingMode() {
  if (!activeSpokeModal) return;
  const saveBtn = $("#mode-save-btn");
  if (saveBtn) saveBtn.disabled = !canManageTenant(activeSpokeModal.tenant_id);
  const res = await apiFetch(`/api/${encodeURIComponent(activeSpokeModal.tenant_id)}/processing-summary`);
  if (!res || !res.ok) return;
  const summary = await res.json();
  const spokeSummary = summary.islands.find(item => item.spoke_id === activeSpokeModal.spoke.id);
  if (!spokeSummary) return;
  $("#mode-global") && ($("#mode-global").value = spokeSummary.global_mode || "centralized");
  const grid = $("#mode-features-grid");
  if (!grid) return;
  grid.innerHTML = PROCESSING_FEATURES.map(feature => `
    <div class="mode-feature-item">
      <label class="mode-feature-label" for="mode-${feature}">${escHtml(feature.replace(/_/g, " "))}</label>
      <select id="mode-${feature}" class="form-input mode-feature-select">
        <option value="inherit">Inherit</option>
        <option value="centralized">Centralized</option>
        <option value="distributed">Distributed</option>
      </select>
    </div>
  `).join("");
  PROCESSING_FEATURES.forEach(feature => {
    const value = spokeSummary.feature_overrides?.[feature];
    const select = $(`#mode-${feature}`);
    if (select) select.value = value || "inherit";
    if (select && !canManageTenant(activeSpokeModal.tenant_id)) select.disabled = true;
  });
  setFormMessage("mode-msg", "", true);
}

async function saveSpokeProcessingMode() {
  if (!activeSpokeModal || !canManageTenant(activeSpokeModal.tenant_id)) return;
  const payload = { global_mode: $("#mode-global")?.value || "centralized" };
  PROCESSING_FEATURES.forEach(feature => {
    const value = $(`#mode-${feature}`)?.value || "inherit";
    payload[feature] = value === "inherit" ? null : value;
  });
  const res = await apiFetch(`/api/${encodeURIComponent(activeSpokeModal.tenant_id)}/spokes/${encodeURIComponent(activeSpokeModal.spoke.id)}/processing-mode`, {
    method: "PATCH",
    body: payload,
  });
  if (!res || !res.ok) {
    const err = await readJson(res);
    setFormMessage("mode-msg", err?.detail || "Failed to save mode.", false);
    return;
  }
  setFormMessage("mode-msg", "Processing mode saved.", true);
  showToast("Processing mode updated.", "ok");
  await loadSpokes(true);
}

function openSpokeModal(spoke, tenantId, subtab = "spoke-clients") {
  activeSpokeModal = { spoke, tenant_id: tenantId };
  $("#spoke-modal-title") && ($("#spoke-modal-title").textContent = `${spokePrimaryLabel(spoke)} — ${tenantName(tenantId)}`);
  $("#spoke-modal")?.classList.remove("hidden");
  activateSpokeSubtab(subtab);
  renderSpokeClientsTab();
  loadSpokeCommands();
  loadSpokeProcessingMode();
  loadSpokeAudit();
}

function closeSpokeModal() {
  $("#spoke-modal")?.classList.add("hidden");
  activeSpokeModal = null;
}

function activateSpokeSubtab(subtabId) {
  $$(".spoke-subtab").forEach(button => button.classList.toggle("active", button.dataset.subtab === subtabId));
  ["spoke-clients", "spoke-commands", "spoke-mode", "spoke-audit"].forEach(panelId => {
    document.getElementById(panelId)?.classList.toggle("hidden", panelId !== subtabId);
  });
  if (subtabId === "spoke-commands") loadSpokeCommands();
  if (subtabId === "spoke-mode") loadSpokeProcessingMode();
  if (subtabId === "spoke-audit") loadSpokeAudit();
}

async function sendSpokeCommand(type) {
  if (!activeSpokeModal) return;
  const ok = await sendCommandToSpoke(activeSpokeModal.tenant_id, activeSpokeModal.spoke.id, type);
  if (ok) {
    loadSpokeCommands();
    loadSpokeAudit();
  }
}
window.sendSpokeCommand = sendSpokeCommand;

async function loadSettings() {
  if (!currentTenantId) return;
  const apiBase = `${window.location.origin}/api/${currentTenantId}/spokes/{id}`;
  $("#api-register-url") && ($("#api-register-url").textContent = `${window.location.origin}/api/spokes/register`);
  $("#api-telemetry-url") && ($("#api-telemetry-url").textContent = `POST ${apiBase}/telemetry`);
  $("#api-inbox-url") && ($("#api-inbox-url").textContent = `GET ${apiBase}/inbox`);
  $("#api-ack-url") && ($("#api-ack-url").textContent = `POST ${apiBase}/ack`);
  const disabled = !canManageTenant();
  ["aruba-save-btn", "notif-save-btn", "acme-request-btn"].forEach(id => { const btn = document.getElementById(id); if (btn) btn.disabled = disabled; });
  // Load tenant admin pending spokes whenever settings tab opens
  if (canManageTenant() && !currentUser?.is_superadmin) loadTenantPendingSpokes();
  const res = await apiFetch(`/api/${encodeURIComponent(currentTenantId)}/settings`);
  if (!res || !res.ok) return;
  const data = await res.json();
  const aruba = data.aruba || {};
  const notifications = data.notifications || {};
  $("#aruba-api-version") && ($("#aruba-api-version").value = aruba.api_version || "classic");
  $("#aruba-cluster-url") && ($("#aruba-cluster-url").value = aruba.cluster_url || "");
  $("#aruba-client-id") && ($("#aruba-client-id").value = aruba.client_id || "");
  $("#aruba-customer-id") && ($("#aruba-customer-id").value = aruba.customer_id || data.tenant?.aruba_cid || "");
  $("#notif-enabled") && ($("#notif-enabled").checked = Boolean(notifications.enabled));
  $("#notif-teams") && ($("#notif-teams").value = notifications.teams_webhook_url || "");
  $("#notif-smtp-host") && ($("#notif-smtp-host").value = notifications.smtp_host || "");
  $("#notif-smtp-port") && ($("#notif-smtp-port").value = notifications.smtp_port || 587);
  $("#notif-smtp-user") && ($("#notif-smtp-user").value = notifications.smtp_user || "");
  $("#notif-to-emails") && ($("#notif-to-emails").value = (notifications.to_emails || []).join(", "));
  await loadAcmeSettings();
}

async function savePassword() {
  const current_password = $("#pw-current")?.value || "";
  const new_password = $("#pw-new")?.value || "";
  const confirm = $("#pw-confirm")?.value || "";
  if (!current_password || !new_password) {
    setFormMessage("pw-msg", "Enter current and new password.", false);
    return;
  }
  if (new_password !== confirm) {
    setFormMessage("pw-msg", "Passwords do not match.", false);
    return;
  }
  const res = await apiFetch("/api/auth/change-password", { method: "POST", body: { current_password, new_password } });
  if (!res || !res.ok) {
    const err = await readJson(res);
    setFormMessage("pw-msg", err?.detail || "Unable to change password.", false);
    return;
  }
  setFormMessage("pw-msg", "Password updated.", true);
  ["pw-current", "pw-new", "pw-confirm"].forEach(id => { const input = document.getElementById(id); if (input) input.value = ""; });
}

async function saveArubaSettings() {
  if (!currentTenantId) return;
  const payload = {
    api_version: $("#aruba-api-version")?.value || "classic",
    cluster_url: $("#aruba-cluster-url")?.value.trim() || "",
    client_id: $("#aruba-client-id")?.value.trim() || "",
    client_secret: $("#aruba-client-secret")?.value || "",
    customer_id: $("#aruba-customer-id")?.value.trim() || "",
  };
  const res = await apiFetch(`/api/${encodeURIComponent(currentTenantId)}/settings/aruba`, { method: "POST", body: payload });
  if (!res || !res.ok) {
    const err = await readJson(res);
    setFormMessage("aruba-msg", err?.detail || "Unable to save Aruba settings.", false);
    return;
  }
  setFormMessage("aruba-msg", "Aruba settings saved.", true);
  $("#aruba-client-secret") && ($("#aruba-client-secret").value = "");
}

async function saveNotificationSettings() {
  if (!currentTenantId) return;
  const payload = {
    enabled: Boolean($("#notif-enabled")?.checked),
    teams_webhook_url: $("#notif-teams")?.value.trim() || "",
    smtp_host: $("#notif-smtp-host")?.value.trim() || "",
    smtp_port: Number($("#notif-smtp-port")?.value || 587),
    smtp_user: $("#notif-smtp-user")?.value.trim() || "",
    smtp_pass: $("#notif-smtp-pass")?.value || "",
    to_emails: $("#notif-to-emails")?.value || "",
  };
  const res = await apiFetch(`/api/${encodeURIComponent(currentTenantId)}/settings/notifications`, { method: "POST", body: payload });
  if (!res || !res.ok) {
    const err = await readJson(res);
    setFormMessage("notif-msg", err?.detail || "Unable to save notifications.", false);
    return;
  }
  setFormMessage("notif-msg", "Notifications saved.", true);
  $("#notif-smtp-pass") && ($("#notif-smtp-pass").value = "");
}

function showKeyBanner(apiKey, spokeId) {
  const banner = $("#sa-key-banner");
  if (!banner) return;
  banner.innerHTML = `
    <strong>⚠ Save this API key — it will not be shown again.</strong>
    <div class="api-key-display">${escHtml(apiKey)}</div>
    <div class="row">
      <span>Spoke ${escHtml(spokeId)} approved.</span>
      <button class="btn btn-secondary btn-small" id="sa-key-dismiss" type="button">Dismiss</button>
    </div>
  `;
  banner.classList.remove("hidden");
  $("#sa-key-dismiss")?.addEventListener("click", () => banner.classList.add("hidden"), { once: true });
}



function acmeBadgeClass(daysRemaining) {
  if (typeof daysRemaining !== "number" || Number.isNaN(daysRemaining)) return "badge-grey";
  if (daysRemaining > 30) return "badge-green";
  if (daysRemaining >= 10) return "badge-yellow";
  return "badge-red";
}

function toggleAcmeDnsSection() {
  const challenge = $("#acme-challenge")?.value || "http-01";
  const isDns = challenge === "dns-01";
  $("#acme-dns-section")?.classList.toggle("hidden", !isDns);
  if (isDns) {
    const provider = $("#acme-dns-provider")?.value || "cloudflare";
    $("#acme-cloudflare-fields")?.classList.toggle("hidden", provider !== "cloudflare");
    $("#acme-he-fields")?.classList.toggle("hidden", provider !== "hurricane_electric");
  }
}

function renderAcmeStatus(certInfo = {}, cfg = {}) {
  const container = $("#acme-cert-status");
  if (!container) return;
  if (!certInfo || certInfo.source === "none") {
    container.innerHTML = `
      <div class="setup-status-item"><span class="setup-status-label">Certificate</span><span class="setup-status-value">Not configured</span></div>
      <div class="setup-status-item"><span class="setup-status-label">Challenge</span><span class="setup-status-value">${escHtml(cfg.challenge || "http-01")}</span></div>
      <div class="setup-status-item"><span class="setup-status-label">Authority</span><span class="setup-status-value">${escHtml(cfg.ca || "letsencrypt")}</span></div>
      <div class="setup-status-item"><span class="setup-status-label">Last Error</span><span class="setup-status-value muted">${escHtml(cfg.last_error || "—")}</span></div>
    `;
    return;
  }
  const days = Number(certInfo.days_remaining ?? 0);
  container.innerHTML = `
    <div class="setup-status-item"><span class="setup-status-label">Domain</span><span class="setup-status-value">${escHtml(certInfo.domain || cfg.domain || "—")}</span></div>
    <div class="setup-status-item"><span class="setup-status-label">Expires</span><span class="setup-status-value">${escHtml(certInfo.expires || "—")} <span class="badge ${acmeBadgeClass(days)}">${Number.isFinite(days) ? `${days} days` : "unknown"}</span></span></div>
    <div class="setup-status-item"><span class="setup-status-label">Issuer</span><span class="setup-status-value">${escHtml(certInfo.issuer || "—")}</span></div>
    <div class="setup-status-item"><span class="setup-status-label">Source</span><span class="setup-status-value">${escHtml(certInfo.source || "—")}</span></div>
  `;
}

async function loadAcmeSettings() {
  const res = await apiFetch("/api/settings/acme");
  if (!res || !res.ok) return;
  const data = await res.json();
  $("#acme-domain") && ($("#acme-domain").value = data.domain || "");
  $("#acme-email") && ($("#acme-email").value = data.email || "");
  $("#acme-ca") && ($("#acme-ca").value = data.ca || "letsencrypt");
  $("#acme-challenge") && ($("#acme-challenge").value = data.challenge || "http-01");
  $("#acme-dns-provider") && ($("#acme-dns-provider").value = data.dns_provider || "cloudflare");
  $("#acme-enabled") && ($("#acme-enabled").checked = Boolean(data.enabled));
  $("#acme-cf-token") && ($("#acme-cf-token").value = "");
  toggleAcmeDnsSection();
  renderAcmeStatus(data.cert_info || {}, data);
}

async function saveAcmeConfig() {
  const payload = {
    enabled: Boolean($("#acme-enabled")?.checked),
    domain: $("#acme-domain")?.value.trim() || "",
    email: $("#acme-email")?.value.trim() || "",
    ca: $("#acme-ca")?.value || "letsencrypt",
    challenge: $("#acme-challenge")?.value || "http-01",
    dns_provider: $("#acme-dns-provider")?.value || "",
    dns_credentials: {
      cf_api_token: $("#acme-cf-token")?.value || "",
      he_ddns_key: $("#acme-he-ddns-key")?.value || "",
    },
  };
  const res = await apiFetch("/api/settings/acme", { method: "POST", body: payload });
  if (!res || !res.ok) {
    const err = await readJson(res);
    setFormMessage("acme-msg", err?.detail || "Unable to save ACME settings.", false);
    return;
  }
  const data = await res.json();
  setFormMessage("acme-msg", "TLS certificate settings saved.", true);
  renderAcmeStatus(data.cert_info || {}, data);
  $("#acme-cf-token") && ($("#acme-cf-token").value = "");
  $("#acme-he-ddns-key") && ($("#acme-he-ddns-key").value = "");
}

async function requestAcmeCert() {
  const button = $("#acme-request-btn");
  if (button) {
    button.disabled = true;
    button.textContent = "Requesting certificate…";
  }
  setFormMessage("acme-msg", "Requesting certificate… (this may take 60-90 seconds)", true);
  try {
    const res = await apiFetch("/api/settings/acme/request", { method: "POST" });
    const data = await readJson(res);
    if (!res || !res.ok || !data?.success) {
      setFormMessage("acme-msg", data?.error || data?.detail || "Certificate request failed.", false);
      return;
    }
    setFormMessage("acme-msg", `Certificate issued for ${data.domain} — expires ${data.expires || "unknown"}.`, true);
    await loadAcmeSettings();
  } catch (error) {
    setFormMessage("acme-msg", error.message || "Certificate request failed.", false);
  } finally {
    if (button) {
      button.disabled = !canManageTenant();
      button.textContent = "Request Certificate Now";
    }
  }
}

window.saveAcmeConfig = saveAcmeConfig;
window.requestAcmeCert = requestAcmeCert;

async function loadSuperadmin() {
  if (!currentUser?.is_superadmin) return;
  const [tenantsRes, pendingRes, usersRes] = await Promise.all([
    apiFetch("/api/superadmin/tenants"),
    apiFetch("/api/superadmin/pending-spokes"),
    apiFetch("/api/superadmin/users"),
  ]);
  if (tenantsRes?.ok) {
    const tenantData = await tenantsRes.json();
    tenants = tenantData.map(item => ({ id: item.id, name: item.name || item.id, raw: item }));
    buildTenantSelector();
    buildSuperadminTenantTabs();
    renderSuperadminTenants(tenantData);
  }
  if (pendingRes?.ok) renderPendingSpokes(await pendingRes.json());
  if (usersRes?.ok) renderSuperadminUsers(await usersRes.json());
  loadGkillState();
}

function renderPendingSpokes(items) {
  $("#sa-pending-count") && ($("#sa-pending-count").textContent = String(items.length));
  const tbody = $("#sa-pending-tbody");
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No pending spokes.</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(item => `
    <tr>
      <td><strong>${escHtml(item.spoke_name || item.hostname)}</strong></td>
      <td><code>${escHtml(item.hostname)}</code></td>
      <td>${item.tenant_hint
        ? `<span class="role-badge" style="background:var(--hpe-green,#01a982)">${escHtml(tenantName(item.tenant_hint))}</span>`
        : '<span class="muted">—</span>'}</td>
      <td>${escHtml(fmtDate(item.registered_at))}</td>
      <td>
        <select class="form-input form-input-sm sa-tenant-assign" data-pending-id="${escHtml(item.id)}">
          ${tenants.map(tenant => `<option value="${escHtml(tenant.id)}"${item.tenant_hint === tenant.id ? ' selected' : ''}>${escHtml(tenant.name)}</option>`).join("")}
        </select>
      </td>
      <td>
        <button class="btn btn-primary btn-small" data-approve-id="${escHtml(item.id)}" type="button">Approve</button>
        <button class="btn btn-danger btn-small" data-reject-id="${escHtml(item.id)}" type="button">Reject</button>
      </td>
    </tr>
  `).join("");
}

// ── Tenant admin pending spokes ──────────────────────────────────────────────
async function loadTenantPendingSpokes() {
  if (!currentTenantId || !canManageTenant()) return;
  try {
    const res = await fetch(`/api/tenant/${currentTenantId}/pending-spokes`,
      { headers: { Authorization: `Bearer ${authToken}` } });
    if (!res.ok) return;
    const items = await res.json();
    renderTenantPendingSpokes(items);
  } catch (_) { /* silent */ }
}

function renderTenantPendingSpokes(items) {
  const btn = document.getElementById("settings-pending-tab-btn");
  const countEl = document.getElementById("settings-pending-count");
  if (btn) btn.style.display = items.length > 0 ? "" : "none";
  if (countEl) countEl.textContent = String(items.length);
  const tbody = document.getElementById("settings-pending-tbody");
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No pending spokes for this tenant.</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(item => `
    <tr>
      <td><strong>${escHtml(item.spoke_name || item.hostname)}</strong></td>
      <td><code>${escHtml(item.hostname)}</code></td>
      <td>${escHtml(fmtDate(item.registered_at))}</td>
      <td>
        <button class="btn btn-primary btn-small" data-tenant-approve-id="${escHtml(item.id)}" type="button">Approve</button>
        <button class="btn btn-danger btn-small" data-tenant-reject-id="${escHtml(item.id)}" type="button">Reject</button>
      </td>
    </tr>
  `).join("");
  // wire approve/reject
  tbody.querySelectorAll("[data-tenant-approve-id]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.tenantApproveId;
      const res = await fetch(`/api/tenant/${currentTenantId}/pending-spokes/${id}/approve`,
        { method: "POST", headers: { Authorization: `Bearer ${authToken}` } });
      if (!res.ok) { alert("Approval failed: " + (await res.text())); return; }
      const data = await res.json();
      const banner = document.getElementById("settings-pending-key-banner");
      if (banner && data.api_key) {
        banner.textContent = `✅ Spoke approved. API Key (shown once): ${data.api_key}`;
        banner.classList.remove("hidden");
        setTimeout(() => banner.classList.add("hidden"), 30000);
      }
      loadTenantPendingSpokes();
    });
  });
  tbody.querySelectorAll("[data-tenant-reject-id]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.tenantRejectId;
      await fetch(`/api/tenant/${currentTenantId}/pending-spokes/${id}`,
        { method: "DELETE", headers: { Authorization: `Bearer ${authToken}` } });
      loadTenantPendingSpokes();
    });
  });
}


function renderSuperadminTenants(items) {
  $("#sa-tenants-count") && ($("#sa-tenants-count").textContent = String(items.length));
  const tbody = $("#sa-tenants-tbody");
  if (!tbody) return;
  tbody.innerHTML = items.length ? items.map(item => {
    const spokeCount = Object.values(spokeCache).reduce((sum, arr) => sum + arr.filter(spoke => spoke.tenant_id === item.id).length, 0);
    return `
      <tr>
        <td>${escHtml(item.name)}</td>
        <td>${escHtml(item.id)}</td>
        <td>${item.has_aruba_config ? "Yes" : "No"}</td>
        <td>${spokeCount}</td>
        <td><button class="btn btn-danger btn-small" data-delete-tenant="${escHtml(item.id)}" type="button">Delete</button></td>
      </tr>
    `;
  }).join("") : '<tr><td colspan="5" class="empty-state">No tenants found.</td></tr>';
}

function renderUserRoles(user) {
  if (user.is_superadmin) return '<span class="role-badge">SUPERADMIN</span>';
  return user.tenant_roles?.length ? user.tenant_roles.map(role => `
    <span class="tenant-role-chip">${escHtml(role.tenant_id)} · ${escHtml(role.role)} <button data-remove-role="${escHtml(user.id)}:${escHtml(role.tenant_id)}" type="button">×</button></span>
  `).join("") : "—";
}

function renderSuperadminUsers(users) {
  $("#sa-users-count") && ($("#sa-users-count").textContent = String(users.length));
  const tbody = $("#sa-users-tbody");
  if (!tbody) return;
  tbody.innerHTML = users.length ? users.map(user => `
    <tr>
      <td>${escHtml(user.username)}</td>
      <td>${user.is_superadmin ? "superadmin" : "tenant-scoped"}</td>
      <td><div class="tenant-role-list">${renderUserRoles(user)}</div></td>
      <td>
        ${user.is_superadmin ? "—" : `
          <div class="inline-form-row">
            <select class="form-input form-input-sm user-tenant-select" data-user-id="${escHtml(user.id)}">
              ${tenants.map(tenant => `<option value="${escHtml(tenant.id)}">${escHtml(tenant.name)}</option>`).join("")}
            </select>
            <select class="form-input form-input-sm user-role-select" data-user-id="${escHtml(user.id)}">
              <option value="admin">Admin</option>
              <option value="operator">Operator</option>
            </select>
            <button class="btn btn-secondary btn-small" data-assign-role="${escHtml(user.id)}" type="button">Assign</button>
            <button class="btn btn-danger btn-small" data-delete-user="${escHtml(user.id)}" type="button">Delete</button>
          </div>
        `}
      </td>
    </tr>
  `).join("") : '<tr><td colspan="4" class="empty-state">No users found.</td></tr>';
}

async function loadGkillState() {
  const res = await apiFetch("/api/superadmin/gkill-state");
  if (!res || !res.ok) return;
  const data = await res.json();
  $("#sa-gkill-value") && ($("#sa-gkill-value").textContent = String(data.value || "—"));
  $("#sa-gkill-fetched") && ($("#sa-gkill-fetched").textContent = data.last_fetched ? fmtDate(new Date(data.last_fetched * 1000).toISOString()) : "—");
  $("#sa-gkill-error") && ($("#sa-gkill-error").textContent = data.error || "—");
  updateGkillBadge(data.value);
}

async function approvePendingSpoke(id) {
  const select = $(`.sa-tenant-assign[data-pending-id="${CSS.escape(id)}"]`);
  const tenantId = select?.value;
  if (!tenantId) return;
  const res = await apiFetch(`/api/superadmin/pending-spokes/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    body: { tenant_id: tenantId },
  });
  if (!res || !res.ok) {
    const err = await readJson(res);
    showToast(err?.detail || "Failed to approve spoke.", "err");
    return;
  }
  const data = await res.json();
  showKeyBanner(data.api_key, data.spoke_id);
  showToast("Spoke approved.", "ok");
  await Promise.all([loadSuperadmin(), loadSpokes(true), loadDashboard()]);
}

async function rejectPendingSpoke(id) {
  const res = await apiFetch(`/api/superadmin/pending-spokes/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res || !res.ok) {
    showToast("Failed to reject spoke.", "err");
    return;
  }
  showToast("Pending spoke rejected.", "ok");
  loadSuperadmin();
}

function openSuperadminTenantForm() {
  if (!currentUser?.is_superadmin) {
    showToast("Only superadmins can add tenants.", "warn");
    return;
  }
  showTab("superadmin", { source: "admin" });
  const tenantsButton = $('.sa-subtab[data-subtab="sa-tenants"]');
  if (tenantsButton) tenantsButton.click();
  $("#sa-tenant-form")?.classList.remove("hidden");
  $("#sa-tenant-name")?.focus();
}

async function createTenant() {
  const name = $("#sa-tenant-name")?.value.trim();
  const aruba_cid = $("#sa-tenant-cid")?.value.trim() || null;
  if (!name) {
    setFormMessage("sa-tenant-msg", "Tenant name is required.", false);
    return;
  }
  const res = await apiFetch("/api/superadmin/tenants", { method: "POST", body: { name, aruba_cid } });
  if (!res || !res.ok) {
    const err = await readJson(res);
    setFormMessage("sa-tenant-msg", err?.detail || "Unable to create tenant.", false);
    return;
  }
  setFormMessage("sa-tenant-msg", "Tenant created.", true);
  $("#sa-tenant-name") && ($("#sa-tenant-name").value = "");
  $("#sa-tenant-cid") && ($("#sa-tenant-cid").value = "");
  $("#sa-tenant-form")?.classList.add("hidden");
  await loadSuperadmin();
}

async function deleteTenant(id) {
  if (!window.confirm(`Delete tenant ${id}?`)) return;
  const res = await apiFetch(`/api/superadmin/tenants/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res || !res.ok) {
    showToast("Failed to delete tenant.", "err");
    return;
  }
  if (currentTenantId === id) { currentTenantId = tenants.find(tenant => tenant.id !== id)?.id || null; tenantContextActive = false; }
  showToast("Tenant deleted.", "ok");
  await loadSuperadmin();
}

async function createUser() {
  const username = $("#sa-new-username")?.value.trim();
  const password = $("#sa-new-password")?.value || "";
  if (!username || !password) {
    setFormMessage("sa-user-msg", "Username and password are required.", false);
    return;
  }
  const res = await apiFetch("/api/superadmin/users", { method: "POST", body: { username, password } });
  if (!res || !res.ok) {
    const err = await readJson(res);
    setFormMessage("sa-user-msg", err?.detail || "Unable to create user.", false);
    return;
  }
  setFormMessage("sa-user-msg", "User created.", true);
  $("#sa-new-username") && ($("#sa-new-username").value = "");
  $("#sa-new-password") && ($("#sa-new-password").value = "");
  loadSuperadmin();
}

async function deleteUser(userId) {
  if (!window.confirm("Delete this user?")) return;
  const res = await apiFetch(`/api/superadmin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
  if (!res || !res.ok) {
    showToast("Failed to delete user.", "err");
    return;
  }
  showToast("User deleted.", "ok");
  loadSuperadmin();
}

async function assignRole(userId) {
  const tenantId = $(`.user-tenant-select[data-user-id="${CSS.escape(userId)}"]`)?.value;
  const role = $(`.user-role-select[data-user-id="${CSS.escape(userId)}"]`)?.value || "operator";
  if (!tenantId) return;
  const res = await apiFetch(`/api/superadmin/users/${encodeURIComponent(userId)}/roles`, { method: "POST", body: { tenant_id: tenantId, role } });
  if (!res || !res.ok) {
    showToast("Failed to assign role.", "err");
    return;
  }
  showToast("Role assigned.", "ok");
  loadSuperadmin();
}

async function removeRole(userId, tenantId) {
  const res = await apiFetch(`/api/superadmin/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(tenantId)}`, { method: "DELETE" });
  if (!res || !res.ok) {
    showToast("Failed to remove role.", "err");
    return;
  }
  showToast("Role removed.", "ok");
  loadSuperadmin();
}

function applyOnlineState(root, online) {
  root.querySelectorAll("[data-online-state] .status-dot, .spoke-section-header > .status-dot").forEach(dot => {
    dot.className = `status-dot ${online ? "online" : "offline"}`;
  });
}

function updateOnlineBadges(spokeOnline) {
  if (!spokeOnline) return;
  document.querySelectorAll("[data-spoke-id]").forEach(node => {
    const tenantId = node.dataset.tenantId;
    const spokeId = node.dataset.spokeId;
    const online = spokeOnline?.[tenantId]?.[spokeId];
    if (typeof online === "boolean") applyOnlineState(node, online);
  });
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
  if (autoRefreshCountdownTimer) {
    clearInterval(autoRefreshCountdownTimer);
    autoRefreshCountdownTimer = null;
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  const toggle = $("#auto-refresh-toggle");
  const intervalSelect = $("#auto-refresh-interval");
  const countdown = $("#auto-refresh-countdown");
  if (!toggle?.checked) {
    if (countdown) countdown.textContent = "—";
    return;
  }
  const seconds = parseInt(intervalSelect?.value || "10", 10);
  autoRefreshSecondsLeft = seconds;
  if (countdown) countdown.textContent = `${autoRefreshSecondsLeft}s`;
  autoRefreshCountdownTimer = setInterval(() => {
    autoRefreshSecondsLeft = Math.max(0, autoRefreshSecondsLeft - 1);
    if (countdown) countdown.textContent = `${autoRefreshSecondsLeft}s`;
  }, 1000);
  autoRefreshTimer = setInterval(async () => {
    autoRefreshSecondsLeft = seconds;
    if (countdown) countdown.textContent = `${autoRefreshSecondsLeft}s`;
    await refreshCurrentView(false);
  }, seconds * 1000);
}

function connectWebSocket() {
  if (ws && [WebSocket.OPEN, WebSocket.CONNECTING].includes(ws.readyState)) return;
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${window.location.host}/ws`);
  ws.onopen = () => updateApiStatus(true, "Connected");
  ws.onmessage = event => {
    const data = JSON.parse(event.data);
    if (data.type === "telemetry") {
      if (activeTab === "spokes") scheduleReload("ws-spokes", () => loadSpokes(true));
      if (activeTab === "dashboard") scheduleReload("ws-dashboard", () => loadDashboard());
      if (activeSpokeModal && data.tenant_id === activeSpokeModal.tenant_id && data.spoke_id === activeSpokeModal.spoke.id) {
        scheduleReload("ws-modal", () => loadSpokes(true).then(() => renderSpokeClientsTab()));
      }
    } else if (data.type === "heartbeat_update") {
      updateOnlineBadges(data.island_online);
    } else if (data.type === "gkill_switch_update") {
      updateGkillBadge(data.value);
    } else if (data.type === "notification") {
      showToast(data.message, data.level === "warning" ? "warn" : "ok");
    } else if (data.type === "cert_renewed") {
      showToast(`TLS certificate renewed — expires ${data.expires || "unknown"}`, "ok");
      if (activeTab === "settings") loadAcmeSettings();
    } else if (data.type === "pending_spoke_registered") {
      if (currentUser?.is_superadmin && activeTab === "superadmin") loadSuperadmin();
      if (canManageTenant() && !currentUser?.is_superadmin && data.tenant_hint === currentTenantId) {
        loadTenantPendingSpokes();
        showToast(`New spoke '${data.spoke_name || data.hostname}' is pending approval.`, "ok");
      }
    } else if (data.type === "task_result") {
      showToast(`Spoke ${data.spoke_id}: ${data.task_type} ${data.status}`, data.status === "success" ? "ok" : "err");
      if (activeSpokeModal && data.spoke_id === activeSpokeModal.spoke.id) {
        loadSpokeCommands();
        loadSpokeAudit();
      }
    }
  };
  ws.onclose = () => {
    updateApiStatus(false, "Disconnected");
    ws = null;
    wsReconnectTimer = window.setTimeout(connectWebSocket, 3000);
  };
  ws.onerror = () => {
    if (ws && ws.readyState !== WebSocket.CLOSED) ws.close();
  };
}

function bindEvents() {
  document.addEventListener("click", event => {
    const adminShortcut = event.target.closest("[data-admin-tab]");
    if (adminShortcut) {
      showTab(adminShortcut.dataset.adminTab, { source: "admin" });
      return;
    }

    if (event.target.closest("#tenant-context-change-btn")) {
      showTab("dashboard", { source: "admin" });
      return;
    }

    const tabButton = event.target.closest("#tab-nav .tab");
    if (tabButton) {
      if (tabButton.dataset.tenantId) setCurrentTenant(tabButton.dataset.tenantId, false);
      showTab(tabButton.dataset.tab, { button: tabButton, source: tabButton.closest("#tenant-context-nav") ? "tenant" : "admin" });
      return;
    }

    const enterTenantButton = event.target.closest("[data-enter-tenant]");
    if (enterTenantButton) {
      tenantContextActive = true;
      setCurrentTenant(enterTenantButton.dataset.enterTenant, false).then(() => showTab("spokes", { source: "tenant" }));
      return;
    }

    if (event.target.closest("[data-add-tenant]")) {
      openSuperadminTenantForm();
      return;
    }

    const setupButton = event.target.closest(".settings-subtab");
    if (setupButton) {
      const subtab = setupButton.dataset.subtab;
      $$(".settings-subtab").forEach(button => button.classList.toggle("active", button.dataset.subtab === subtab));
      ["settings-account", "settings-aruba", "settings-notifications", "settings-api", "settings-tls"].forEach(panelId => {
        document.getElementById(panelId)?.classList.toggle("hidden", panelId !== subtab);
      });
      return;
    }

    const saButton = event.target.closest(".sa-subtab");
    if (saButton) {
      const subtab = saButton.dataset.subtab;
      $$(".sa-subtab").forEach(button => button.classList.toggle("active", button.dataset.subtab === subtab));
      ["sa-pending", "sa-tenants", "sa-users", "sa-gkill"].forEach(panelId => {
        document.getElementById(panelId)?.classList.toggle("hidden", panelId !== subtab);
      });
      return;
    }

    const spokeSubtab = event.target.closest(".spoke-subtab");
    if (spokeSubtab) {
      activateSpokeSubtab(spokeSubtab.dataset.subtab);
      return;
    }

    if (event.target.matches("[data-approve-id]")) approvePendingSpoke(event.target.dataset.approveId);
    if (event.target.matches("[data-reject-id]")) rejectPendingSpoke(event.target.dataset.rejectId);
    if (event.target.matches("[data-delete-tenant]")) deleteTenant(event.target.dataset.deleteTenant);
    if (event.target.matches("[data-delete-user]")) deleteUser(event.target.dataset.deleteUser);
    if (event.target.matches("[data-assign-role]")) assignRole(event.target.dataset.assignRole);
    if (event.target.matches("[data-remove-role]")) {
      const [userId, tenantId] = event.target.dataset.removeRole.split(":");
      removeRole(userId, tenantId);
    }
  });

  $("#login-btn")?.addEventListener("click", openLoginModal);
  $("#logout-btn")?.addEventListener("click", () => logout(true));
  $("#login-submit-btn")?.addEventListener("click", submitLogin);
  $("#login-cancel-btn")?.addEventListener("click", closeLoginModal);
  $("#login-modal")?.addEventListener("click", event => { if (event.target === event.currentTarget) closeLoginModal(); });
  $("#login-password")?.addEventListener("keydown", event => { if (event.key === "Enter") submitLogin(); });
  $("#refresh-dashboard-btn")?.addEventListener("click", () => loadDashboard(true));
  $("#dashboard-add-tenant-btn")?.addEventListener("click", openSuperadminTenantForm);
  $("#refresh-spokes-btn")?.addEventListener("click", () => loadSpokes(true));
  $("#refresh-commands-btn")?.addEventListener("click", loadCommands);
  $("#auto-refresh-toggle")?.addEventListener("change", startAutoRefresh);
  $("#auto-refresh-interval")?.addEventListener("change", startAutoRefresh);
  $("#send-command-btn")?.addEventListener("click", sendCommandFromForm);
  $("#collapse-all-btn")?.addEventListener("click", () => { getExpandedSet().clear(); loadSpokes(); });
  $("#expand-all-btn")?.addEventListener("click", async () => {
    const spokes = await ensureSpokes();
    spokeUiState.expandedByTenant[currentTenantId] = new Set(spokes.filter(spoke => spoke.status === "approved").map(spoke => spoke.id));
    loadSpokes();
  });
  $("#spoke-search")?.addEventListener("input", event => {
    spokeUiState.search = event.target.value || "";
    scheduleReload("spoke-search", () => loadSpokes(), 120);
  });
  $("#spoke-modal-close")?.addEventListener("click", closeSpokeModal);
  $("#spoke-modal")?.addEventListener("click", event => { if (event.target === event.currentTarget) closeSpokeModal(); });
  $("#mode-save-btn")?.addEventListener("click", saveSpokeProcessingMode);
  $("#pw-save-btn")?.addEventListener("click", savePassword);
  $("#aruba-save-btn")?.addEventListener("click", saveArubaSettings);
  $("#notif-save-btn")?.addEventListener("click", saveNotificationSettings);
  $("#sa-gkill-refresh-btn")?.addEventListener("click", loadGkillState);
  $("#sa-add-tenant-btn")?.addEventListener("click", () => $("#sa-tenant-form")?.classList.toggle("hidden"));
  $("#sa-cancel-tenant-btn")?.addEventListener("click", () => $("#sa-tenant-form")?.classList.add("hidden"));
  $("#sa-save-tenant-btn")?.addEventListener("click", createTenant);
  $("#sa-create-user-btn")?.addEventListener("click", createUser);
}

(async function init() {
  bindEvents();
  await pingApi();
  if (authToken) await loadUserContext();
  connectWebSocket();
  if (currentUser && currentTenantId) await ensureSpokes(true);
  syncTenantContextChrome();
  syncHubPermissionUI();
  await loadDashboard();
  startAutoRefresh();
})();

document.getElementById("acme-challenge")?.addEventListener("change", toggleAcmeDnsSection);
document.getElementById("acme-dns-provider")?.addEventListener("change", toggleAcmeDnsSection);
