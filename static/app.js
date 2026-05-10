"use strict";

let authToken = localStorage.getItem("hub_token") || null;
let currentUser = null;
let currentTenantId = null;
let tenants = [];
let islandCache = {};
let activeIslandModal = null;
let ws = null;
let wsReconnectTimer = null;
let activeTab = "dashboard";
let autoRefreshTimer = null;
let autoRefreshCountdownTimer = null;
let autoRefreshSecondsLeft = 10;

const PROCESSING_FEATURES = ["aruba_polling", "teams_webhook", "email", "heartbeat", "gkill", "schedules", "repo_sync"];
const islandUiState = { expandedByTenant: {}, search: "" };
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
    const badge = $("#build-version");
    if (badge && data?.version) {
      badge.textContent = `v${data.version}`;
      badge.title = `Branch: ${data.branch || "?"} | SHA: ${data.sha || "?"}`;
    }
  }
}

function getExpandedSet(tenantId = currentTenantId) {
  if (!tenantId) return new Set();
  if (!islandUiState.expandedByTenant[tenantId]) islandUiState.expandedByTenant[tenantId] = new Set();
  return islandUiState.expandedByTenant[tenantId];
}

function syncRoleBadge() {
  const badge = $("#topbar-role-badge");
  if (!badge || !currentUser) return;
  badge.textContent = currentUser.is_superadmin ? "SUPERADMIN" : (currentRoleForTenant() || "user").toUpperCase();
}

function buildTenantSelector() {
  const wrap = $("#tenant-selector");
  const select = $("#tenant-select");
  if (!wrap || !select) return;
  select.innerHTML = tenants.map(tenant => `<option value="${escHtml(tenant.id)}">${escHtml(tenant.name)}</option>`).join("");
  if (currentTenantId) select.value = currentTenantId;
  wrap.classList.toggle("hidden", !(currentUser && (currentUser.is_superadmin || tenants.length > 1)));
}

function clearDynamicTenantTabs() {
  $$(".dynamic-tenant-tab").forEach(tab => tab.remove());
}

function buildSuperadminTenantTabs() {
  clearDynamicTenantTabs();
  const islandsTab = $('.tab[data-tab="islands"]');
  const superTab = $('.tab[data-tab="superadmin"]');
  if (!currentUser?.is_superadmin || !islandsTab || !superTab) {
    if (islandsTab) islandsTab.classList.remove("hidden");
    return;
  }
  islandsTab.classList.add("hidden");
  superTab.textContent = "⚙ Admin";
  tenants.forEach(tenant => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "tab auth-tab dynamic-tenant-tab";
    button.dataset.tab = "islands";
    button.dataset.tenantId = tenant.id;
    button.textContent = tenant.name;
    superTab.parentNode.insertBefore(button, superTab);
  });
}

function applyAuthUI() {
  const loggedIn = Boolean(currentUser && authToken);
  $("#login-btn")?.classList.toggle("hidden", loggedIn);
  $("#topbar-user")?.classList.toggle("hidden", !loggedIn);
  $("#topbar-username") && ($("#topbar-username").textContent = currentUser?.username || "");
  $$(".auth-tab").forEach(tab => tab.classList.toggle("hidden", !loggedIn));
  $(".superadmin-tab")?.classList.toggle("hidden", !(loggedIn && currentUser?.is_superadmin));
  if (!loggedIn) {
    currentTenantId = null;
    tenants = [];
    islandCache = {};
    clearDynamicTenantTabs();
    $("#tenant-selector")?.classList.add("hidden");
    $(".tab[data-tab='islands']")?.classList.remove("hidden");
    $(".tab[data-tab='superadmin']") && ($(".tab[data-tab='superadmin']").textContent = "🔑 Superadmin");
    if (activeTab !== "dashboard") showTab("dashboard");
    return;
  }
  buildTenantSelector();
  syncRoleBadge();
  buildSuperadminTenantTabs();
  const settingsTab = $('.tab[data-tab="settings"]');
  settingsTab?.classList.toggle("hidden", !canManageTenant() && !currentUser.is_superadmin);
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
  populateCommandIslandSelect();
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
  tenants = [];
  islandCache = {};
  activeIslandModal = null;
  localStorage.removeItem("hub_token");
  applyAuthUI();
  closeIslandModal();
  if (showMessage) showToast("Signed out.", "ok");
}

async function setCurrentTenant(tenantId, reload = true) {
  currentTenantId = tenantId;
  $("#tenant-select") && ($("#tenant-select").value = tenantId || "");
  syncRoleBadge();
  applyAuthUI();
  populateCommandIslandSelect();
  if (reload && ["islands", "commands", "settings"].includes(activeTab)) await refreshCurrentView(true);
}

function showTab(tabId, opts = {}) {
  if (["islands", "commands", "settings", "superadmin"].includes(tabId) && !currentUser) {
    openLoginModal();
    return;
  }
  activeTab = tabId;
  $$(".tab-content").forEach(panel => panel.classList.add("hidden"));
  const panel = document.getElementById(`tab-${tabId}`);
  if (panel) panel.classList.remove("hidden");
  $$("#tab-nav .tab").forEach(button => button.classList.remove("active"));
  if (opts.button) {
    opts.button.classList.add("active");
  } else if (currentUser?.is_superadmin && tabId === "islands" && currentTenantId) {
    const tenantButton = $(`.dynamic-tenant-tab[data-tenant-id="${CSS.escape(currentTenantId)}"]`);
    if (tenantButton) tenantButton.classList.add("active");
  } else {
    $(`#tab-nav .tab[data-tab="${tabId}"]`)?.classList.add("active");
  }
  refreshCurrentView();
}

async function refreshCurrentView(force = false) {
  if (activeTab === "dashboard") {
    await loadDashboard();
  } else if (activeTab === "islands") {
    await loadIslands(force);
  } else if (activeTab === "commands") {
    await loadCommands();
  } else if (activeTab === "settings") {
    await loadSettings();
  } else if (activeTab === "superadmin") {
    await loadSuperadmin();
  }
}

function getTenantIslands() {
  return currentTenantId ? (islandCache[currentTenantId] || []) : [];
}

function spokeLabel(count) {
  return `${count} ${count === 1 ? "spoke" : "spokes"}`;
}

function updateIslandStatPills(islands) {
  const approved = islands.filter(island => island.status === "approved");
  const onlineCount = approved.filter(island => isOnline(island.last_seen)).length;
  const clientCount = approved.reduce((sum, island) => sum + ((island.telemetry?.clients || []).length), 0);
  $("#islands-count-pill") && ($("#islands-count-pill").textContent = spokeLabel(approved.length));
  $("#islands-online-pill") && ($("#islands-online-pill").textContent = `${onlineCount} online`);
  $("#islands-clients-pill") && ($("#islands-clients-pill").textContent = `${clientCount} clients`);
}

async function loadDashboard() {
  const res = await fetch("/api/sites").catch(() => null);
  if (!res || !res.ok) return;
  const sites = (await res.json()).filter(site => site.status === "approved");
  const grid = $("#dashboard-grid");
  const empty = $("#dashboard-empty");
  const onlineCount = sites.filter(site => isOnline(site.last_seen)).length;
  const clientCount = sites.reduce((sum, site) => sum + ((site.telemetry?.clients || []).length), 0);
  $("#dash-islands-pill") && ($("#dash-islands-pill").textContent = spokeLabel(sites.length));
  $("#dash-clients-pill") && ($("#dash-clients-pill").textContent = `${clientCount} clients`);
  $("#dash-online-pill") && ($("#dash-online-pill").textContent = `${onlineCount} online`);
  empty?.classList.toggle("hidden", sites.length > 0);
  if (!grid) return;
  renderInBatches("dashboard", grid, sites, site => {
    const online = isOnline(site.last_seen);
    const clients = site.telemetry?.clients || [];
    const card = document.createElement("article");
    card.className = "island-card compact-card";
    card.dataset.tenantId = site.workspace_id || site.tenant_id || "";
    card.dataset.islandId = site.id;
    card.innerHTML = `
      <div class="island-card-header-row">
        <div class="island-card-title-wrap">
          <div class="island-card-title">${escHtml(site.hostname)}</div>
          <div class="island-card-subtitle">${escHtml(site.label || site.workspace_id || "—")}</div>
        </div>
        <div class="island-card-status" data-online-state>${statusDot(online)}</div>
      </div>
      <div class="island-card-meta">
        <span class="stat-pill">${clients.length} clients</span>
        <span class="stat-pill">${online ? "Online" : "Offline"}</span>
      </div>
      <div class="island-card-footer">Last seen ${escHtml(relativeTime(site.last_seen))}</div>
    `;
    return card;
  }, 60);
}

async function ensureIslands(force = false) {
  if (!currentTenantId) return [];
  if (!force && islandCache[currentTenantId]) return islandCache[currentTenantId];
  const res = await apiFetch(`/api/${encodeURIComponent(currentTenantId)}/islands`);
  if (!res || !res.ok) return [];
  const islands = await res.json();
  islandCache[currentTenantId] = islands;
  populateCommandIslandSelect();
  return islands;
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

function renderIslandBody(section, island) {
  const body = $(".island-section-body", section);
  if (!body) return;
  const clients = island.telemetry?.clients || [];
  body.innerHTML = `
    <div class="island-section-summary">
      <span class="stat-pill">Workspace ${escHtml(tenantName(island.tenant_id))}</span>
      <span class="stat-pill">${clients.length} clients</span>
      <span class="stat-pill">Seen ${escHtml(relativeTime(island.last_seen))}</span>
    </div>
    <div class="island-action-bar">
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
    <table class="data-table island-client-table">
      <thead><tr><th>Client ID</th><th>Hostname</th><th>Status</th><th>Last Seen</th><th>IP</th></tr></thead>
      <tbody>${renderClientRows(clients)}</tbody>
    </table>
  `;
  const quickSelect = $(".quick-command-select", body);
  if (!canManageTenant(island.tenant_id)) {
    const modeButton = $('[data-action="mode"]', body);
    if (modeButton) modeButton.disabled = true;
  }
  body.addEventListener("click", async event => {
    const action = event.target.closest("[data-action]")?.dataset.action;
    if (!action) return;
    if (action === "detail") openIslandModal(island, island.tenant_id, "island-clients");
    if (action === "audit") openIslandModal(island, island.tenant_id, "island-audit");
    if (action === "mode") openIslandModal(island, island.tenant_id, "island-mode");
    if (action === "send") await sendCommandToIsland(island.tenant_id, island.id, quickSelect?.value || "kill_switch");
  }, { once: true });
}

function createIslandSection(island) {
  const expanded = getExpandedSet().has(island.id);
  const online = isOnline(island.last_seen);
  const clients = island.telemetry?.clients || [];
  const section = document.createElement("section");
  section.className = "island-section";
  section.dataset.islandId = island.id;
  section.dataset.tenantId = island.tenant_id;
  section.innerHTML = `
    <div class="island-section-header">
      <span class="island-toggle ${expanded ? "open" : ""}">▶</span>
      ${statusDot(online)}
      <span class="island-hostname">${escHtml(island.hostname)}</span>
      <span class="island-label-inline">${escHtml(island.label || "—")}</span>
      <span class="island-meta">${clients.length} clients · ${escHtml(relativeTime(island.last_seen))}</span>
    </div>
    <div class="island-section-body ${expanded ? "expanded" : ""}"></div>
  `;
  $(".island-section-header", section)?.addEventListener("click", event => {
    if (event.target.closest("button,select,input,a")) return;
    toggleIslandSection(section, island);
  });
  if (expanded) {
    renderIslandBody(section, island);
    $(".island-section-body", section).dataset.rendered = "1";
  }
  return section;
}

function toggleIslandSection(section, island) {
  const expandedSet = getExpandedSet();
  const body = $(".island-section-body", section);
  const toggle = $(".island-toggle", section);
  const opening = !body.classList.contains("expanded");
  body.classList.toggle("expanded", opening);
  toggle?.classList.toggle("open", opening);
  if (opening) {
    expandedSet.add(island.id);
    if (!body.dataset.rendered) {
      renderIslandBody(section, island);
      body.dataset.rendered = "1";
    }
  } else {
    expandedSet.delete(island.id);
  }
}

async function loadIslands(force = false) {
  const islands = await ensureIslands(force);
  updateIslandStatPills(islands);
  const search = islandUiState.search.trim().toLowerCase();
  const filtered = islands.filter(island => island.status === "approved" && (!search || island.hostname.toLowerCase().includes(search)));
  const list = $("#islands-list");
  const empty = $("#islands-empty");
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
  renderInBatches("islands", $(".workspace-body", group), filtered, island => createIslandSection(island), 30);
}

function populateCommandIslandSelect() {
  const select = $("#cmd-island");
  if (!select) return;
  const islands = getTenantIslands().filter(island => island.status === "approved");
  select.innerHTML = islands.map(island => `<option value="${escHtml(island.id)}">${escHtml(island.hostname)}</option>`).join("");
}

async function sendCommandToIsland(tenantId, islandId, type) {
  const response = await apiFetch("/api/commands", {
    method: "POST",
    body: { tenant_id: tenantId, island_id: islandId, type, target: "island", payload: {} },
  });
  if (!response || !response.ok) {
    const err = await readJson(response);
    showToast(err?.detail || `Failed to send ${type}.`, "err");
    return false;
  }
  showToast(`${type} queued for ${islandId}.`, "ok");
  if (activeTab === "commands") loadCommands();
  if (activeIslandModal?.island?.id === islandId) loadIslandCommands();
  return true;
}

async function loadCommands() {
  if (!currentTenantId) return;
  await ensureIslands();
  populateCommandIslandSelect();
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
    const island = getTenantIslands().find(item => item.id === command.island_id);
    return `
      <tr>
        <td>${escHtml(island?.hostname || command.island_id)}</td>
        <td>${escHtml(command.type)}</td>
        <td><span class="badge cmd-status-${escHtml(command.status)}">${escHtml(command.status)}</span></td>
        <td>${escHtml(fmtDate(command.created_at))}</td>
        <td>${escHtml(fmtDate(command.expires_at))}</td>
      </tr>
    `;
  }).join("");
}

async function sendCommandFromForm() {
  const islandId = $("#cmd-island")?.value;
  const type = $("#cmd-type")?.value || "kill_switch";
  if (!currentTenantId || !islandId) {
    setFormMessage("cmd-msg", "Select a spoke first.", false);
    return;
  }
  const ok = await sendCommandToIsland(currentTenantId, islandId, type);
  setFormMessage("cmd-msg", ok ? "Command queued." : "Failed to queue command.", ok);
  if (ok) loadCommands();
}

function getIslandFromCache(tenantId, islandId) {
  return (islandCache[tenantId] || []).find(island => island.id === islandId) || null;
}

function renderIslandClientsTab() {
  const island = getIslandFromCache(activeIslandModal?.tenant_id, activeIslandModal?.island?.id) || activeIslandModal?.island;
  if (!island) return;
  activeIslandModal.island = island;
  const tbody = $("#island-clients-tbody");
  if (!tbody) return;
  tbody.innerHTML = renderClientRows(island.telemetry?.clients || []);
}

async function loadIslandCommands() {
  if (!activeIslandModal) return;
  const { tenant_id: tenantId, island } = activeIslandModal;
  const res = await apiFetch(`/api/${encodeURIComponent(tenantId)}/commands?island_id=${encodeURIComponent(island.id)}`);
  if (!res || !res.ok) return;
  const commands = await res.json();
  const tbody = $("#island-cmds-tbody");
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

async function loadIslandAudit() {
  if (!activeIslandModal) return;
  const { tenant_id: tenantId, island } = activeIslandModal;
  const res = await apiFetch(`/api/${encodeURIComponent(tenantId)}/islands/${encodeURIComponent(island.id)}/audit`);
  if (!res || !res.ok) return;
  const audit = (await res.json()).slice(-20).reverse();
  const tbody = $("#island-audit-tbody");
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

async function loadIslandProcessingMode() {
  if (!activeIslandModal) return;
  const saveBtn = $("#mode-save-btn");
  if (saveBtn) saveBtn.disabled = !canManageTenant(activeIslandModal.tenant_id);
  const res = await apiFetch(`/api/${encodeURIComponent(activeIslandModal.tenant_id)}/processing-summary`);
  if (!res || !res.ok) return;
  const summary = await res.json();
  const islandSummary = summary.islands.find(item => item.island_id === activeIslandModal.island.id);
  if (!islandSummary) return;
  $("#mode-global") && ($("#mode-global").value = islandSummary.global_mode || "centralized");
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
    const value = islandSummary.feature_overrides?.[feature];
    const select = $(`#mode-${feature}`);
    if (select) select.value = value || "inherit";
    if (select && !canManageTenant(activeIslandModal.tenant_id)) select.disabled = true;
  });
  setFormMessage("mode-msg", "", true);
}

async function saveIslandProcessingMode() {
  if (!activeIslandModal || !canManageTenant(activeIslandModal.tenant_id)) return;
  const payload = { global_mode: $("#mode-global")?.value || "centralized" };
  PROCESSING_FEATURES.forEach(feature => {
    const value = $(`#mode-${feature}`)?.value || "inherit";
    payload[feature] = value === "inherit" ? null : value;
  });
  const res = await apiFetch(`/api/${encodeURIComponent(activeIslandModal.tenant_id)}/islands/${encodeURIComponent(activeIslandModal.island.id)}/processing-mode`, {
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
  await loadIslands(true);
}

function openIslandModal(island, tenantId, subtab = "island-clients") {
  activeIslandModal = { island, tenant_id: tenantId };
  $("#island-modal-title") && ($("#island-modal-title").textContent = `${island.hostname} — ${tenantName(tenantId)}`);
  $("#island-modal")?.classList.remove("hidden");
  activateIslandSubtab(subtab);
  renderIslandClientsTab();
  loadIslandCommands();
  loadIslandProcessingMode();
  loadIslandAudit();
}

function closeIslandModal() {
  $("#island-modal")?.classList.add("hidden");
  activeIslandModal = null;
}

function activateIslandSubtab(subtabId) {
  $$(".island-subtab").forEach(button => button.classList.toggle("active", button.dataset.subtab === subtabId));
  ["island-clients", "island-commands", "island-mode", "island-audit"].forEach(panelId => {
    document.getElementById(panelId)?.classList.toggle("hidden", panelId !== subtabId);
  });
  if (subtabId === "island-commands") loadIslandCommands();
  if (subtabId === "island-mode") loadIslandProcessingMode();
  if (subtabId === "island-audit") loadIslandAudit();
}

async function sendIslandCommand(type) {
  if (!activeIslandModal) return;
  const ok = await sendCommandToIsland(activeIslandModal.tenant_id, activeIslandModal.island.id, type);
  if (ok) {
    loadIslandCommands();
    loadIslandAudit();
  }
}
window.sendIslandCommand = sendIslandCommand;

async function loadSettings() {
  if (!currentTenantId) return;
  const apiBase = `${window.location.origin}/api/${currentTenantId}/islands/{id}`;
  $("#api-register-url") && ($("#api-register-url").textContent = `${window.location.origin}/api/islands/register`);
  $("#api-telemetry-url") && ($("#api-telemetry-url").textContent = `POST ${apiBase}/telemetry`);
  $("#api-inbox-url") && ($("#api-inbox-url").textContent = `GET ${apiBase}/inbox`);
  $("#api-ack-url") && ($("#api-ack-url").textContent = `POST ${apiBase}/ack`);
  const disabled = !canManageTenant();
  ["aruba-save-btn", "notif-save-btn", "acme-request-btn"].forEach(id => { const btn = document.getElementById(id); if (btn) btn.disabled = disabled; });
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

function showKeyBanner(apiKey, islandId) {
  const banner = $("#sa-key-banner");
  if (!banner) return;
  banner.innerHTML = `
    <strong>⚠ Save this API key — it will not be shown again.</strong>
    <div class="api-key-display">${escHtml(apiKey)}</div>
    <div class="row">
      <span>Spoke ${escHtml(islandId)} approved.</span>
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
  $("#acme-dns-section")?.classList.toggle("hidden", challenge !== "dns-01");
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
    apiFetch("/api/superadmin/pending-islands"),
    apiFetch("/api/superadmin/users"),
  ]);
  if (tenantsRes?.ok) {
    const tenantData = await tenantsRes.json();
    tenants = tenantData.map(item => ({ id: item.id, name: item.name || item.id, raw: item }));
    buildTenantSelector();
    buildSuperadminTenantTabs();
    renderSuperadminTenants(tenantData);
  }
  if (pendingRes?.ok) renderPendingIslands(await pendingRes.json());
  if (usersRes?.ok) renderSuperadminUsers(await usersRes.json());
  loadGkillState();
}

function renderPendingIslands(items) {
  $("#sa-pending-count") && ($("#sa-pending-count").textContent = String(items.length));
  const tbody = $("#sa-pending-tbody");
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No pending spokes.</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(item => `
    <tr>
      <td><code>${escHtml(item.hostname)}</code></td>
      <td>${escHtml(item.label || "—")}</td>
      <td>${escHtml(fmtDate(item.registered_at))}</td>
      <td>
        <select class="form-input form-input-sm sa-tenant-assign" data-pending-id="${escHtml(item.id)}">
          ${tenants.map(tenant => `<option value="${escHtml(tenant.id)}">${escHtml(tenant.name)}</option>`).join("")}
        </select>
      </td>
      <td>
        <button class="btn btn-primary btn-small" data-approve-id="${escHtml(item.id)}" type="button">Approve</button>
        <button class="btn btn-danger btn-small" data-reject-id="${escHtml(item.id)}" type="button">Reject</button>
      </td>
    </tr>
  `).join("");
}

function renderSuperadminTenants(items) {
  $("#sa-tenants-count") && ($("#sa-tenants-count").textContent = String(items.length));
  const tbody = $("#sa-tenants-tbody");
  if (!tbody) return;
  tbody.innerHTML = items.length ? items.map(item => {
    const islandCount = Object.values(islandCache).reduce((sum, arr) => sum + arr.filter(island => island.tenant_id === item.id).length, 0);
    return `
      <tr>
        <td>${escHtml(item.name)}</td>
        <td>${escHtml(item.id)}</td>
        <td>${item.has_aruba_config ? "Yes" : "No"}</td>
        <td>${islandCount}</td>
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
  $("#sa-gkill-fetched") && ($("#sa-gkill-fetched").textContent = data.last_fetched ? fmtDate(new Date(data.last_fetched * 1000).toISOString()) : "—"));
  $("#sa-gkill-error") && ($("#sa-gkill-error").textContent = data.error || "—");
  updateGkillBadge(data.value);
}

async function approvePendingIsland(id) {
  const select = $(`.sa-tenant-assign[data-pending-id="${CSS.escape(id)}"]`);
  const tenantId = select?.value;
  if (!tenantId) return;
  const res = await apiFetch(`/api/superadmin/pending-islands/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    body: { tenant_id: tenantId },
  });
  if (!res || !res.ok) {
    const err = await readJson(res);
    showToast(err?.detail || "Failed to approve spoke.", "err");
    return;
  }
  const data = await res.json();
  showKeyBanner(data.api_key, data.island_id);
  showToast("Spoke approved.", "ok");
  await Promise.all([loadSuperadmin(), loadIslands(true), loadDashboard()]);
}

async function rejectPendingIsland(id) {
  const res = await apiFetch(`/api/superadmin/pending-islands/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res || !res.ok) {
    showToast("Failed to reject spoke.", "err");
    return;
  }
  showToast("Pending spoke rejected.", "ok");
  loadSuperadmin();
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
  if (currentTenantId === id) currentTenantId = tenants.find(tenant => tenant.id !== id)?.id || null;
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
  root.querySelectorAll("[data-online-state] .status-dot, .island-section-header > .status-dot").forEach(dot => {
    dot.className = `status-dot ${online ? "online" : "offline"}`;
  });
}

function updateOnlineBadges(islandOnline) {
  if (!islandOnline) return;
  document.querySelectorAll("[data-island-id]").forEach(node => {
    const tenantId = node.dataset.tenantId;
    const islandId = node.dataset.islandId;
    const online = islandOnline?.[tenantId]?.[islandId];
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
      if (activeTab === "islands") scheduleReload("ws-islands", () => loadIslands(true));
      if (activeTab === "dashboard") scheduleReload("ws-dashboard", () => loadDashboard());
      if (activeIslandModal && data.tenant_id === activeIslandModal.tenant_id && data.island_id === activeIslandModal.island.id) {
        scheduleReload("ws-modal", () => loadIslands(true).then(() => renderIslandClientsTab()));
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
    } else if (data.type === "task_result") {
      showToast(`Spoke ${data.island_id}: ${data.task_type} ${data.status}`, data.status === "success" ? "ok" : "err");
      if (activeIslandModal && data.island_id === activeIslandModal.island.id) {
        loadIslandCommands();
        loadIslandAudit();
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
    const tabButton = event.target.closest("#tab-nav .tab");
    if (tabButton) {
      if (tabButton.dataset.tenantId) setCurrentTenant(tabButton.dataset.tenantId, false);
      showTab(tabButton.dataset.tab, { button: tabButton });
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

    const islandSubtab = event.target.closest(".island-subtab");
    if (islandSubtab) {
      activateIslandSubtab(islandSubtab.dataset.subtab);
      return;
    }

    if (event.target.matches("[data-approve-id]")) approvePendingIsland(event.target.dataset.approveId);
    if (event.target.matches("[data-reject-id]")) rejectPendingIsland(event.target.dataset.rejectId);
    if (event.target.matches("[data-delete-tenant]")) deleteTenant(event.target.dataset.deleteTenant);
    if (event.target.matches("[data-delete-user]")) deleteUser(event.target.dataset.deleteUser);
    if (event.target.matches("[data-assign-role]")) assignRole(event.target.dataset.assignRole);
    if (event.target.matches("[data-remove-role]")) {
      const [userId, tenantId] = event.target.dataset.removeRole.split(":");
      removeRole(userId, tenantId);
    }
  });

  $("#tenant-select")?.addEventListener("change", event => setCurrentTenant(event.target.value));
  $("#login-btn")?.addEventListener("click", openLoginModal);
  $("#logout-btn")?.addEventListener("click", () => logout(true));
  $("#login-submit-btn")?.addEventListener("click", submitLogin);
  $("#login-cancel-btn")?.addEventListener("click", closeLoginModal);
  $("#login-modal")?.addEventListener("click", event => { if (event.target === event.currentTarget) closeLoginModal(); });
  $("#login-password")?.addEventListener("keydown", event => { if (event.key === "Enter") submitLogin(); });
  $("#refresh-dashboard-btn")?.addEventListener("click", loadDashboard);
  $("#refresh-islands-btn")?.addEventListener("click", () => loadIslands(true));
  $("#refresh-commands-btn")?.addEventListener("click", loadCommands);
  $("#auto-refresh-toggle")?.addEventListener("change", startAutoRefresh);
  $("#auto-refresh-interval")?.addEventListener("change", startAutoRefresh);
  $("#send-command-btn")?.addEventListener("click", sendCommandFromForm);
  $("#collapse-all-btn")?.addEventListener("click", () => { getExpandedSet().clear(); loadIslands(); });
  $("#expand-all-btn")?.addEventListener("click", async () => {
    const islands = await ensureIslands();
    islandUiState.expandedByTenant[currentTenantId] = new Set(islands.filter(island => island.status === "approved").map(island => island.id));
    loadIslands();
  });
  $("#island-search")?.addEventListener("input", event => {
    islandUiState.search = event.target.value || "";
    scheduleReload("island-search", () => loadIslands(), 120);
  });
  $("#island-modal-close")?.addEventListener("click", closeIslandModal);
  $("#island-modal")?.addEventListener("click", event => { if (event.target === event.currentTarget) closeIslandModal(); });
  $("#mode-save-btn")?.addEventListener("click", saveIslandProcessingMode);
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
  if (currentUser && currentTenantId) await ensureIslands(true);
  await loadDashboard();
  startAutoRefresh();
})();

document.getElementById("acme-challenge")?.addEventListener("change", toggleAcmeDnsSection);
