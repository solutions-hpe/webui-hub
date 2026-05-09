'use strict';

// ── Auth state ────────────────────────────────────────────────────
let authToken = localStorage.getItem('csw_token') || null;
let currentUser = null;

// ── API helper ────────────────────────────────────────────────────
async function apiFetch(url, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
  const res = await fetch(url, { ...opts, headers });
  if (res.status === 401) { logout(); return null; }
  return res;
}

// ── Toast notifications ───────────────────────────────────────────
function showToast(msg, level = 'ok') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'settings-message ' + (level === 'ok' ? 'success' : 'error');
  toast.textContent = msg;
  toast.style.cssText = 'min-width:240px;max-width:380px;box-shadow:0 4px 16px rgba(0,0,0,0.15);cursor:pointer;';
  toast.addEventListener('click', () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
}

// ── Tab switching ─────────────────────────────────────────────────
let activeTab = 'dashboard';

function showTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
    btn.setAttribute('aria-selected', btn.dataset.tab === tabId ? 'true' : 'false');
  });
  const panel = document.getElementById('tab-' + tabId);
  if (panel) panel.classList.remove('hidden');
  activeTab = tabId;
  if (tabId === 'dashboard') loadDashboard();
  else if (tabId === 'sites') loadSites();
  else if (tabId === 'workspaces') loadWorkspaces();
  else if (tabId === 'checks') loadChecks();
  else if (tabId === 'commands') loadCommands();
  else if (tabId === 'settings') setupSettingsTab();
}

// ── Settings sub-tabs ─────────────────────────────────────────────
function activateSettingsSubtab(subtabId) {
  document.querySelectorAll('.settings-subtab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.subtab === subtabId);
  });
  document.querySelectorAll('#tab-settings .setup-subpanel').forEach(panel => {
    panel.classList.toggle('hidden', panel.id !== subtabId);
  });
}

// ── Auth ──────────────────────────────────────────────────────────
async function checkAuth() {
  if (!authToken) { updateAuthUI(false); return; }
  const res = await apiFetch('/api/auth/me');
  if (!res || !res.ok) { logout(); return; }
  currentUser = await res.json();
  updateAuthUI(true);
}

function updateAuthUI(loggedIn) {
  const loginBtn = document.getElementById('login-btn');
  const topbarUser = document.getElementById('topbar-user');
  const usernameEl = document.getElementById('topbar-username');
  const mgmtTabs = document.querySelectorAll('.management-tab');

  if (loggedIn && currentUser) {
    loginBtn.classList.add('hidden');
    topbarUser.classList.remove('hidden');
    if (usernameEl) usernameEl.textContent = currentUser.username;
    mgmtTabs.forEach(t => t.classList.remove('hidden'));
    // Set API info URL
    const regUrl = document.getElementById('api-register-url');
    if (regUrl) regUrl.textContent = window.location.origin + '/api/islands/register';
  } else {
    loginBtn.classList.remove('hidden');
    topbarUser.classList.add('hidden');
    mgmtTabs.forEach(t => t.classList.add('hidden'));
    // If on a management tab, switch to dashboard
    if (activeTab !== 'dashboard') showTab('dashboard');
  }
}

function openLoginModal() {
  document.getElementById('login-modal').classList.remove('hidden');
  document.getElementById('login-username').focus();
}

function closeLoginModal() {
  document.getElementById('login-modal').classList.add('hidden');
  document.getElementById('login-error').textContent = '';
  document.getElementById('login-username').value = '';
  document.getElementById('login-password').value = '';
}

async function submitLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  errEl.textContent = '';
  if (!username || !password) { errEl.textContent = 'Enter username and password.'; return; }

  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    errEl.textContent = err.detail || 'Invalid credentials.';
    return;
  }

  const data = await res.json();
  authToken = data.access_token;
  localStorage.setItem('csw_token', authToken);
  closeLoginModal();
  await checkAuth();
  showToast('Signed in successfully.', 'ok');
}

function logout() {
  authToken = null;
  currentUser = null;
  localStorage.removeItem('csw_token');
  updateAuthUI(false);
  showToast('Signed out.', 'ok');
}

// ── Dashboard ─────────────────────────────────────────────────────
async function loadDashboard() {
  const res = await fetch('/api/sites');
  if (!res || !res.ok) return;
  const sites = await res.json();

  const grid = document.getElementById('dashboard-grid');
  const empty = document.getElementById('dashboard-empty');
  const sitesPill = document.getElementById('dash-sites-pill');
  const clientsPill = document.getElementById('dash-clients-pill');
  const lastUpdated = document.getElementById('dash-last-updated');

  const approved = sites.filter(s => s.status === 'approved');
  if (sitesPill) sitesPill.textContent = `${approved.length} site${approved.length !== 1 ? 's' : ''}`;

  let totalClients = 0;
  approved.forEach(s => {
    try { const t = JSON.parse(s.telemetry_json || '{}'); totalClients += (t.clients || []).length; } catch {}
  });
  if (clientsPill) clientsPill.textContent = `${totalClients} client${totalClients !== 1 ? 's' : ''}`;
  if (lastUpdated) lastUpdated.textContent = new Date().toLocaleTimeString();

  if (!approved.length) {
    grid.textContent = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  grid.innerHTML = '';

  approved.forEach(site => {
    const telemetry = (() => { try { return JSON.parse(site.telemetry_json || '{}'); } catch { return {}; } })();
    const isOnline = site.last_seen && (Date.now() / 1000 - new Date(site.last_seen).getTime() / 1000) < 120;

    const card = document.createElement('div');
    card.className = 'site-card';

    card.innerHTML = `
      <div class="site-card-header">
        <div>
          <p class="site-card-hostname">${escHtml(site.hostname)}</p>
          <p class="site-card-label">${escHtml(site.label || site.workspace_id || '—')}</p>
        </div>
        <span class="site-status-pill ${isOnline ? 'online' : 'offline'}">
          <span class="status-dot ${isOnline ? 'online' : 'offline'}"></span>
          ${isOnline ? 'Online' : 'Offline'}
        </span>
      </div>
      <div class="site-card-meta">
        <span class="server-stat-pill">👥 ${(telemetry.clients || []).length} clients</span>
        ${site.last_seen ? `<span class="server-stat-pill">🕐 ${relativeTime(site.last_seen)}</span>` : ''}
      </div>`;
    grid.appendChild(card);
  });
}

// ── Sites ─────────────────────────────────────────────────────────
async function loadSites() {
  const res = await apiFetch('/api/sites');
  if (!res || !res.ok) return;
  const sites = await res.json();

  const pending = sites.filter(s => s.status === 'pending');
  const approved = sites.filter(s => s.status === 'approved');

  const pendingSection = document.getElementById('sites-pending-section');
  const pendingTbody = document.getElementById('sites-pending-tbody');
  const approvedTbody = document.getElementById('sites-approved-tbody');
  const pendingCount = document.getElementById('sites-pending-count');
  const approvedCount = document.getElementById('sites-approved-count');
  const countPill = document.getElementById('sites-count-pill');

  if (pendingCount) pendingCount.textContent = pending.length;
  if (approvedCount) approvedCount.textContent = approved.length;
  if (countPill) countPill.textContent = `${sites.length} site${sites.length !== 1 ? 's' : ''}`;

  pendingSection.classList.toggle('hidden', pending.length === 0);

  pendingTbody.innerHTML = '';
  pending.forEach(site => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${escHtml(site.hostname)}</code></td>
      <td>${escHtml(site.label || '—')}</td>
      <td>${fmtDate(site.created_at)}</td>
      <td>${fmtDate(site.last_seen)}</td>
      <td>
        <button class="btn btn-primary btn-small" onclick="approveSite('${site.id}')">Approve</button>
        <button class="btn btn-danger btn-small" onclick="deleteSite('${site.id}')">Delete</button>
      </td>`;
    pendingTbody.appendChild(tr);
  });

  approvedTbody.innerHTML = '';
  approved.forEach(site => {
    const isOnline = site.last_seen && (Date.now() - new Date(site.last_seen).getTime()) < 120000;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${escHtml(site.hostname)}</code></td>
      <td>${escHtml(site.label || '—')}</td>
      <td>${escHtml(site.workspace_id || '—')}</td>
      <td>${fmtDate(site.last_seen)}</td>
      <td><span class="site-status-pill ${isOnline ? 'online' : 'offline'}">${isOnline ? 'Online' : 'Offline'}</span></td>
      <td>
        <button class="btn btn-danger btn-small" onclick="revokeSite('${site.id}')">Revoke</button>
        <button class="btn btn-secondary btn-small" onclick="deleteSite('${site.id}')">Delete</button>
      </td>`;
    approvedTbody.appendChild(tr);
  });
}

async function approveSite(id) {
  const res = await apiFetch(`/api/sites/${id}/approve`, { method: 'POST' });
  if (!res || !res.ok) { showToast('Failed to approve site.', 'err'); return; }
  const data = await res.json();
  if (data.api_key) {
    document.getElementById('key-once-value').textContent = data.api_key;
    document.getElementById('key-once-banner').classList.remove('hidden');
  }
  showToast('Site approved.', 'ok');
  loadSites();
}

async function revokeSite(id) {
  if (!confirm('Revoke this site\'s API key?')) return;
  const res = await apiFetch(`/api/sites/${id}/revoke`, { method: 'POST' });
  if (!res || !res.ok) { showToast('Failed to revoke.', 'err'); return; }
  showToast('Site revoked.', 'ok');
  loadSites();
}

async function deleteSite(id) {
  if (!confirm('Delete this site record?')) return;
  const res = await apiFetch(`/api/sites/${id}`, { method: 'DELETE' });
  if (!res || !res.ok) { showToast('Failed to delete.', 'err'); return; }
  showToast('Site deleted.', 'ok');
  loadSites();
}

// ── Workspaces ────────────────────────────────────────────────────
async function loadWorkspaces() {
  const res = await apiFetch('/api/workspaces');
  if (!res || !res.ok) return;
  const workspaces = await res.json();

  const grid = document.getElementById('workspaces-grid');
  const empty = document.getElementById('workspaces-empty');
  const pill = document.getElementById('workspaces-count-pill');
  if (pill) pill.textContent = `${workspaces.length} workspace${workspaces.length !== 1 ? 's' : ''}`;

  if (!workspaces.length) {
    grid.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  grid.innerHTML = '';

  workspaces.forEach(ws => {
    const card = document.createElement('div');
    card.className = 'setup-card';
    card.innerHTML = `
      <div class="setup-card-header">
        <h2>${escHtml(ws.name)}</h2>
        <p>Ownership: <strong>${ws.ownership}</strong> · Central poll: ${ws.central_poll_enabled ? '✓ on' : '✗ off'}</p>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <span class="server-stat-pill">ID: ${ws.id.slice(0, 8)}…</span>
        ${ws.aruba_workspace_id ? `<span class="server-stat-pill">☁ ${escHtml(ws.aruba_workspace_id)}</span>` : ''}
      </div>
      <div style="margin-top:14px;display:flex;gap:8px;">
        <button class="btn btn-secondary btn-small" onclick="deleteWorkspace('${ws.id}')">Delete</button>
      </div>`;
    grid.appendChild(card);
  });
}

async function deleteWorkspace(id) {
  if (!confirm('Delete this workspace?')) return;
  const res = await apiFetch(`/api/workspaces/${id}`, { method: 'DELETE' });
  if (!res || !res.ok) { showToast('Failed to delete workspace.', 'err'); return; }
  showToast('Workspace deleted.', 'ok');
  loadWorkspaces();
}

// ── Checks ────────────────────────────────────────────────────────
async function loadChecks() {
  const res = await apiFetch('/api/checks');
  if (!res || !res.ok) return;
  const checks = await res.json();

  const tbody = document.getElementById('checks-tbody');
  const pill = document.getElementById('checks-count-pill');
  if (pill) pill.textContent = `${checks.length} check${checks.length !== 1 ? 's' : ''}`;

  tbody.innerHTML = '';
  checks.forEach(chk => {
    const statusCls = chk.status === 'green' ? 'badge-green' : chk.status === 'red' ? 'badge-red' : 'badge-grey';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escHtml(chk.check_name)}</td>
      <td>${escHtml(chk.check_type)}</td>
      <td>${escHtml(chk.workspace_id || '—')}</td>
      <td>${chk.timeout_minutes} min</td>
      <td><span class="badge ${statusCls}">${chk.status}</span></td>
      <td><button class="btn btn-danger btn-small" onclick="deleteCheck('${chk.id}')">Remove</button></td>`;
    tbody.appendChild(tr);
  });

  if (!checks.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No checks configured.</td></tr>';
  }
}

async function deleteCheck(id) {
  if (!confirm('Remove this check?')) return;
  const res = await apiFetch(`/api/checks/${id}`, { method: 'DELETE' });
  if (!res || !res.ok) { showToast('Failed to remove check.', 'err'); return; }
  showToast('Check removed.', 'ok');
  loadChecks();
}

// ── Commands ──────────────────────────────────────────────────────
async function loadCommands() {
  const res = await apiFetch('/api/commands');
  if (!res || !res.ok) return;
  const commands = await res.json();

  const tbody = document.getElementById('commands-tbody');
  const queued = commands.filter(c => c.status === 'queued').length;
  const pill = document.getElementById('commands-count-pill');
  if (pill) pill.textContent = `${queued} queued`;

  tbody.innerHTML = '';
  commands.forEach(cmd => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${escHtml(cmd.target)}</code></td>
      <td>${escHtml(cmd.type)}</td>
      <td><span class="badge cmd-status-${cmd.status}">${cmd.status}</span></td>
      <td>${fmtDate(cmd.created_at)}</td>
      <td>${fmtDate(cmd.executed_at || cmd.delivered_at)}</td>
      <td><button class="btn btn-secondary btn-small" onclick="deleteCommand('${cmd.id}')">✕</button></td>`;
    tbody.appendChild(tr);
  });

  if (!commands.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No commands in queue.</td></tr>';
  }

  // Populate target dropdown
  const targetSel = document.getElementById('cmd-target');
  if (targetSel && targetSel.options.length === 1) {
    const sitesRes = await apiFetch('/api/sites');
    if (sitesRes && sitesRes.ok) {
      const sites = await sitesRes.json();
      sites.filter(s => s.status === 'approved').forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.hostname;
        opt.textContent = s.hostname;
        targetSel.appendChild(opt);
      });
    }
  }
}

async function deleteCommand(id) {
  const res = await apiFetch(`/api/commands/${id}`, { method: 'DELETE' });
  if (!res || !res.ok) { showToast('Failed to delete command.', 'err'); return; }
  loadCommands();
}

async function sendCommand() {
  const target = document.getElementById('cmd-target').value;
  const type = document.getElementById('cmd-type').value;
  const msgEl = document.getElementById('cmd-msg');
  msgEl.textContent = '';
  const res = await apiFetch('/api/commands', {
    method: 'POST',
    body: JSON.stringify({ target, type, payload_json: '{}' }),
  });
  if (!res || !res.ok) {
    msgEl.textContent = 'Failed to send command.';
    msgEl.className = 'form-msg msg-error';
    return;
  }
  msgEl.textContent = 'Command queued.';
  msgEl.className = 'form-msg msg-ok';
  setTimeout(() => { msgEl.textContent = ''; }, 3000);
  loadCommands();
}

// ── Settings tab ──────────────────────────────────────────────────
function setupSettingsTab() {
  const regUrl = document.getElementById('api-register-url');
  if (regUrl) regUrl.textContent = window.location.origin + '/api/islands/register';
}

// ── Helpers ───────────────────────────────────────────────────────
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    const now = new Date();
    const diffMin = Math.round((now - d) / 60000);
    if (diffMin < 2) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffMin < 1440) return `${Math.round(diffMin / 60)}h ago`;
    return d.toLocaleDateString();
  } catch { return '—'; }
}

function relativeTime(iso) { return fmtDate(iso); }

// ── Wiring ────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    if (btn.classList.contains('management-tab') && !authToken) {
      openLoginModal(); return;
    }
    showTab(btn.dataset.tab);
  });
});

document.querySelectorAll('.settings-subtab').forEach(btn => {
  btn.addEventListener('click', () => activateSettingsSubtab(btn.dataset.subtab));
});

document.getElementById('login-btn')?.addEventListener('click', openLoginModal);
document.getElementById('logout-btn')?.addEventListener('click', logout);
document.getElementById('login-submit-btn')?.addEventListener('click', submitLogin);
document.getElementById('login-cancel-btn')?.addEventListener('click', closeLoginModal);
document.getElementById('login-modal')?.addEventListener('click', e => {
  if (e.target === e.currentTarget) closeLoginModal();
});
document.getElementById('login-password')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') submitLogin();
});

document.getElementById('refresh-dashboard-btn')?.addEventListener('click', loadDashboard);
document.getElementById('refresh-sites-btn')?.addEventListener('click', loadSites);
document.getElementById('refresh-commands-btn')?.addEventListener('click', loadCommands);
document.getElementById('send-command-btn')?.addEventListener('click', sendCommand);
document.getElementById('add-workspace-btn')?.addEventListener('click', () => {
  const name = prompt('Workspace name:');
  if (!name) return;
  apiFetch('/api/workspaces', { method: 'POST', body: JSON.stringify({ name }) })
    .then(res => { if (res && res.ok) { showToast('Workspace created.', 'ok'); loadWorkspaces(); } });
});

// ── Init ──────────────────────────────────────────────────────────
(async () => {
  await checkAuth();
  loadDashboard();
  // Ping API status
  try {
    const res = await fetch('/api/auth/me', { headers: authToken ? { Authorization: `Bearer ${authToken}` } : {} });
    const dot = document.getElementById('api-dot');
    const text = document.getElementById('api-text');
    if (dot) dot.className = 'status-dot ' + (res.ok || res.status === 401 ? 'online' : 'offline');
    if (text) text.textContent = res.ok || res.status === 401 ? 'Connected' : 'Error';
  } catch {
    const dot = document.getElementById('api-dot');
    const text = document.getElementById('api-text');
    if (dot) dot.className = 'status-dot offline';
    if (text) text.textContent = 'Disconnected';
  }
})();
