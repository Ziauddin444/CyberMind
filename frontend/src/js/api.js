// ─── CyberMind API Service Layer ────────────────────────────────────────────
// Dual-Backend Architecture:
// - Node.js Backend (port 3001): Authentication & User Management
// - Flask Backend (port 5000): Security Operations (firewall, devices, honeypot)

// Detect if running locally or in production
const isLocal =
  window.location.protocol === 'file:' ||
  window.location.hostname === '' ||
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1';
const AUTH_BASE = isLocal ? 'http://localhost:3001/api' : '/api';  // Node.js auth backend
const OPS_BASE = isLocal ? 'http://localhost:5000/api' : '/api';    // Flask operations backend

function getToken() {
  return localStorage.getItem('cybermind_token');
}

function getUserRole() {
  return localStorage.getItem('cybermind_role') || 'viewer';
}

export function setToken(token, user = null) {
  localStorage.setItem('cybermind_token', token);
  if (user) {
    setUserContext(user);
  }
}

export function clearToken() {
  localStorage.removeItem('cybermind_token');
  localStorage.removeItem('cybermind_role');
}

export function setUserContext(user) {
  const role = user?.role || (user?.isAdmin ? 'admin' : 'viewer');
  localStorage.setItem('cybermind_role', role);
}

// Request helper for any backend
async function request(baseUrl, path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  headers['X-User-Role'] = getUserRole();

  const url = `${baseUrl}${path}`;
  const res = await fetch(url, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('auth:expired'));
    throw new Error('Session expired');
  }

  if (!res.ok) {
    let details = '';
    try {
      const errorBody = await res.json();
      details = errorBody?.error || errorBody?.message || '';
    } catch (_) {
      // Ignore JSON parse errors for non-JSON error responses.
    }
    throw new Error(details ? `API Error: ${res.status} - ${details}` : `API Error: ${res.status}`);
  }
  return res.json();
}

// Auth requests (Node.js backend - port 3001)
async function authRequest(path, options = {}) {
  return request(AUTH_BASE, path, options);
}

// Operations requests (Flask backend - port 5000)
async function opsRequest(path, options = {}) {
  return request(OPS_BASE, path, options);
}

function normalizeOpsDevice(device) {
  return {
    id: device.id,
    name: device.name,
    type: device.device_type || device.type || 'server',
    ip: device.ip_address || device.ip || '',
    status: (device.status || 'offline').toLowerCase(),
    lastThreat: device.lastThreat || 'None',
    safety: Number.isFinite(device.safety) ? device.safety : 95,
    source: 'flask',
  };
}

function mergeDevices(nodeDevices = [], opsDevices = []) {
  const merged = [...nodeDevices];
  const seen = new Set(
    nodeDevices.map((d) => `${String(d.name || '').toLowerCase()}|${String(d.ip || '').toLowerCase()}`)
  );

  for (const d of opsDevices) {
    const normalized = normalizeOpsDevice(d);
    const key = `${String(normalized.name || '').toLowerCase()}|${String(normalized.ip || '').toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(normalized);
    }
  }
  return merged;
}

function normalizeHoneypotLogs(resp) {
  const logs = Array.isArray(resp?.data)
    ? resp.data
    : Array.isArray(resp?.data?.logs)
      ? resp.data.logs
      : [];
  return logs.map((entry) => ({
    id: `hp-${entry.id || `${entry.source_ip || entry.sourceIp || entry.ip_address || entry.ip || 'unknown'}-${entry.timestamp || ''}`}`,
    time: entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--',
    device: entry.source_ip || entry.sourceIp || entry.ip_address || entry.ip || 'Honeypot',
    event: entry.threat_type || 'honeypot_capture',
    summary: entry.payload_preview || `Capture file: ${entry.capture_file || 'unknown'}`,
    action: 'Captured',
    severity: (entry.severity || 'medium').toLowerCase(),
  }));
}

// Auth (Node.js Backend - Port 3001)
export const register = (username, email, password, confirmPassword, name, company) =>
  authRequest('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password, confirmPassword, name, company }) });
export const verifyEmail = (token) =>
  authRequest('/auth/verify-email', { method: 'POST', body: JSON.stringify({ token }) });
export const login = (username, password) =>
  authRequest('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
export const verifyAuth = () => authRequest('/auth/verify');
export const logout = () => authRequest('/auth/logout', { method: 'POST' });
export const forgotPassword = (email) =>
  authRequest('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) });
export const resetPassword = (email, resetCode, newPassword, confirmPassword) =>
  authRequest('/auth/reset-password', { method: 'POST', body: JSON.stringify({ email, resetCode, newPassword, confirmPassword }) });
export const getProfile = () => authRequest('/auth/profile');
export const updateProfile = (data) =>
  authRequest('/auth/profile', { method: 'PUT', body: JSON.stringify(data) });
export const changePassword = (currentPassword, newPassword, confirmPassword) =>
  authRequest('/auth/change-password', { method: 'PUT', body: JSON.stringify({ currentPassword, newPassword, confirmPassword }) });

// Admin (Node.js Backend - Port 3001)
export const getUsers = () => authRequest('/admin/users');
export const getUser = (id) => authRequest(`/admin/users/${id}`);
export const deleteUser = (id) => authRequest(`/admin/users/${id}`, { method: 'DELETE' });
export const makeUserAdmin = (id) => authRequest(`/admin/users/${id}/make-admin`, { method: 'PUT' });
export const removeUserAdmin = (id) => authRequest(`/admin/users/${id}/remove-admin`, { method: 'PUT' });
export const getLoginActivity = () => authRequest('/admin/login-activity');
export const getUserLoginActivity = (username) => authRequest(`/admin/login-activity/user/${username}`);
export const resetUserPassword = (id) => authRequest(`/admin/users/${id}/reset-password`, { method: 'POST' });

// Sessions (Node.js Backend - Port 3001)
export const getSessions = () => authRequest('/sessions');
export const logoutSession = (sessionId) => authRequest(`/sessions/${sessionId}`, { method: 'DELETE' });
export const logoutOtherSessions = () => authRequest('/sessions/logout-others', { method: 'POST' });

// Status (Node.js Backend)
export const getStatus = () => authRequest('/status');

// Real-time dashboard stats from Flask SQLite (Phase 1.2 / 2.1 / 2.3 / 2.4)
export const getFlaskStats = () => opsRequest('/stats');

// Scan history logs from Flask SQLite
export const getScanLogs = () => opsRequest('/logs');

// Dashboard data (Node.js Backend - Port 3001)
// Keep these names for compatibility with frontend app.js
export const getDevices = async () => {
  const [nodeRes, opsRes] = await Promise.allSettled([
    authRequest('/devices'),
    opsRequest('/devices/list'),
  ]);

  const nodeDevices = nodeRes.status === 'fulfilled' ? nodeRes.value : [];
  const opsDevices = opsRes.status === 'fulfilled' ? (opsRes.value?.data || []) : [];

  return mergeDevices(nodeDevices, opsDevices);
};
export const getDevice = (id) => authRequest(`/devices/${id}`);
export const addDevice = (data) => authRequest('/devices', { method: 'POST', body: JSON.stringify(data) });
export const updateDevice = (id, data) => authRequest(`/devices/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const toggleDevice = (id) => authRequest(`/devices/${id}/toggle`, { method: 'PATCH' });
export const deleteDevice = (id) => authRequest(`/devices/${id}`, { method: 'DELETE' });

export const getLogs = async () => {
  const [nodeRes, hpRes, scanRes] = await Promise.allSettled([
    authRequest('/logs'),
    opsRequest('/honeypot/logs'),
    opsRequest('/logs'),                // Flask SQLite scan history (Phase 1.1)
  ]);

  const nodeLogs = nodeRes.status === 'fulfilled' ? nodeRes.value : [];
  const honeypotLogs = hpRes.status === 'fulfilled' ? normalizeHoneypotLogs(hpRes.value) : [];

  // Normalize Flask scan logs into the shared log format
  const rawScanLogs = scanRes.status === 'fulfilled' ? (Array.isArray(scanRes.value) ? scanRes.value : []) : [];
  const flaskScanLogs = rawScanLogs.map((r) => {
    const labelMap = {
      normal: 'success', port_scan: 'warning', brute_force: 'warning',
      ddos: 'warning', malware: 'warning', probe: 'info',
    };
    const severityLabel = r.threat_detected ? (r.severity || 'medium') : 'safe';
    return {
      id: `scan-${r.id}`,
      time: r.timestamp ? new Date(r.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--',
      device: 'Network Scanner',
      event: r.label || 'scan',
      summary: `${r.label || 'scan'} — ${r.packet_count || 0} packets, ${Math.round((r.confidence || 0) * 100)}% confidence (${r.capture_mode || 'live'})`,
      action: r.threat_detected ? 'THREAT DETECTED' : 'NORMAL',
      severity: severityLabel,
      threat_detected: r.threat_detected,
      timestamp: r.timestamp,
      source: 'flask_scan',
    };
  });

  // Merge: scan logs first (most recent events), then honeypot, then Node.js logs
  return [...flaskScanLogs, ...honeypotLogs, ...nodeLogs];
};
export const addLog = (data) => authRequest('/logs', { method: 'POST', body: JSON.stringify(data) });
export const deleteLog = (id) => authRequest(`/logs/${id}`, { method: 'DELETE' });

export const getHoneypot = () => authRequest('/honeypot');
export const deployDecoy = (name) => authRequest('/honeypot/deploy', { method: 'POST', body: JSON.stringify({ name }) });
export const triggerHoneypot = () => authRequest('/honeypot/trigger', { method: 'POST' });

export const checkPhishing = (url) =>
  authRequest('/phishing/check', { method: 'POST', body: JSON.stringify({ url }) });

// ─── Threat Intelligence — reads from Flask SQLite (real scan detections) ────
// FIX: The Node.js /api/threats is always empty (in-memory, never persisted).
// Real detected threats are stored in Flask's SQLite scan_logs table.
// We redirect these to the Flask backend (port 5000) which has the /api/threats
// endpoints that query scan_logs WHERE threat_detected=1.
export const getThreats = () => opsRequest('/threats');
export const getThreat = (id) => opsRequest(`/threats/${id}`);
export const getFlaskThreatsCount = () => opsRequest('/threats/count');

// Kill switch — now accepts reason string; Node.js handler sends to all devices
export const activateKillSwitch = (reason = 'Manual activation') =>
  authRequest('/killswitch', { method: 'POST', body: JSON.stringify({ reason }) });
export const releaseKillSwitch = () =>
  authRequest('/killswitch/release', { method: 'POST', body: JSON.stringify({}) });
// Remediation — accepts playbook number + optional ip/device_id
export const runRemediation = (playbook, ip = null, device_id = null) =>
  authRequest('/remediation', { method: 'POST', body: JSON.stringify({ playbook, ip, device_id }) });
export const translateLog = (rawLog) => authRequest('/logs/translate', { method: 'POST', body: JSON.stringify({ rawLog }) });
export const getLiveFeed = () => authRequest('/live-feed');
export const getSettings = () => authRequest('/settings');
export const updateSettings = (data) => authRequest('/settings', { method: 'PUT', body: JSON.stringify(data) });
export const runScan = () => authRequest('/scan', { method: 'POST' });
export const getAlertConfig = () => authRequest('/alerts/config');
export const updateAlertConfig = (data) => authRequest('/alerts/config', { method: 'PUT', body: JSON.stringify(data) });

// Additional security operations (Flask Backend - Port 5000)
export const opsGetDevices = () => opsRequest('/devices/list');
export const opsGetDevice = (id) => opsRequest(`/devices/${id}`);
// POST /api/devices — canonical Flask endpoint that persists to devices.json
export const opsAddDevice = (data) => opsRequest('/devices', { method: 'POST', body: JSON.stringify(data) });
export const opsUpdateDevice = (id, data) => opsRequest(`/devices/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const opsDeleteDevice = (id) => opsRequest(`/devices/${id}`, { method: 'DELETE' });
export const opsSearchDevices = (query) => opsRequest(`/devices/search?q=${encodeURIComponent(query)}`);
export const opsGetDevicesStatus = () => opsRequest('/devices/status');

export const getFirewallStatus = () => opsRequest('/firewall/status');
export const blockIP = (ip, reason) => opsRequest('/blacklist/ip', { method: 'POST', body: JSON.stringify({ ip_address: ip, reason }) });
// FIX: Fetch blocked IPs from the Node.js backend (port 3001) where /api/detect-attack
// saves all records to blocklist.json. The Flask backend (/blacklist/status) is a
// separate service that may not be running during the professor demo.
// We also normalize the field names so app.js renderBlockedIpList() can read them.
export const getBlacklistStatus = async () => {
  try {
    // FIX: Fetch from Flask backend (port 5000) where the block actually happens
    const response = await opsRequest('/blacklist/status');

    // Flask returns: { success: true, data: { blocked_records: [...] } } 
    // or sometimes just the array directly depending on the service
    const rawData = response.data?.blocked_records || response.data || [];

    // Normalize the data to match exactly what app.js expects
    const normalized = rawData.map((r, index) => ({
      record_id: r.id || r.record_id || `block_${index}`,
      ip_address: r.ip_address || r.ip,
      blocked_at: r.blocked_at || r.detected_at || r.timestamp || new Date().toISOString(),
      status: r.status || 'blocked',
      reason: r.reason || r.attack_type || 'Manual block via dashboard',
    }));

    return {
      data: {
        blocked_records: normalized,
        total: normalized.length
      }
    };
  } catch (err) {
    console.error('Failed to fetch blacklist status from Flask:', err);
    // Return empty array on error so the dashboard doesn't crash
    return { data: { blocked_records: [], total: 0 } };
  }
};
export const unblockIP = (ipAddress) =>
  opsRequest('/blacklist/ip', {
    method: 'DELETE',
    body: JSON.stringify({ ip_address: ipAddress })
  });
export const getIsolationStatus = () => opsRequest('/isolation/status');
export const activateIsolation = () => opsRequest('/isolation/activate', { method: 'POST' });
export const releaseIsolation = () => opsRequest('/isolation/deactivate', { method: 'POST' });

export const getFleetStatus = () => opsRequest('/fleet/status');
export const pingDevice = (ip) => opsRequest('/fleet/ping', { method: 'POST', body: JSON.stringify({ ip }) });
export const performPingSweep = (network) => opsRequest('/fleet/ping_sweep', { method: 'POST', body: JSON.stringify({ network_range: network }) });
export const getNetworkConnections = () => opsRequest('/fleet/connections');
export const registerAsset = (data) => opsRequest('/fleet/register_asset', { method: 'POST', body: JSON.stringify(data) });
export const monitorAssets = () => opsRequest('/fleet/monitor_assets', { method: 'POST' });
export const detectAnomalies = () => opsRequest('/fleet/anomalies');

// Honeypot capture list (legacy — returns metadata objects with id/source_ip/filename)
export const getHoneypotFiles = (limit = 100) => opsRequest(`/honeypot/files?limit=${limit}`);
export const getHoneypotFile = (id) => opsRequest(`/honeypot/files/${id}`);
export const deleteHoneypotCapture = (id) => opsRequest(`/honeypot/files/${id}`, { method: 'DELETE' });
export const exportHoneypotCaptures = (format = 'json') => opsRequest(`/honeypot/files/export?format=${format}`);
export const getHoneypotSummary = () => opsRequest('/honeypot/summary');
export const cleanupHoneypotCaptures = (days = 30) => opsRequest('/honeypot/cleanup', { method: 'POST', body: JSON.stringify({ days }) });

// Honeypot file CRUD by filename — new endpoints
export const opsListHoneypotFiles = () => opsRequest('/honeypot/files-list');
export const opsCreateHoneypotFile = (filename, content) =>
  opsRequest('/honeypot/files', { method: 'POST', body: JSON.stringify({ filename, content }) });
export const opsRenameHoneypotFile = (filename, newFilename) =>
  opsRequest(`/honeypot/files/${encodeURIComponent(filename)}`, {
    method: 'PUT',
    body: JSON.stringify({ new_filename: newFilename }),
  });
export const opsDeleteHoneypotFileByName = (filename) =>
  opsRequest(`/honeypot/files/${encodeURIComponent(filename)}`, { method: 'DELETE' });

// One-click remediation — new /api/remediation endpoint (no auth required)
export const runRemediationAction = (action, ip, threatType = 'unknown', severity = 'high', deviceId = null) =>
  opsRequest('/remediation', {
    method: 'POST',
    body: JSON.stringify({ action, ip, threat_type: threatType, severity, device_id: deviceId }),
  });

export const analyzeEmail = (data) => opsRequest('/phishing/analyze_email', { method: 'POST', body: JSON.stringify(data) });
export const getPhishingStatistics = () => opsRequest('/phishing/statistics');
export const evaluateThreat = (threatData) => opsRequest('/remediation/evaluate_threat', { method: 'POST', body: JSON.stringify(threatData) });
export const getRemediationStatus = () => opsRequest('/remediation/status');
export const getIncidents = () => opsRequest('/remediation/incidents');
export const oneClickRemediation = (threatIP, threatType, severity) => opsRequest('/remediation/one-click', { method: 'POST', body: JSON.stringify({ threat_ip: threatIP, threat_type: threatType, severity }) });
export const manualIncidentResponse = (incidentId, actions) => opsRequest('/remediation/manual_response', { method: 'POST', body: JSON.stringify({ incident_id: incidentId, actions }) });
export const closeIncident = (incidentIndex) => opsRequest('/remediation/close_incident', { method: 'POST', body: JSON.stringify({ incident_index: incidentIndex }) });

/**
 * Translate a threat alert into plain English via Ollama Mistral
 */
export async function translateTraffic(threatData) {
  return request(OPS_BASE, '/traffic/translate', {
    method: 'POST',
    body: JSON.stringify({
      threat_type: threatData.threat_type || 'unknown',
      severity: threatData.severity || 'medium',
      confidence: threatData.confidence || 0.5,
      source_ip: threatData.source_ip || 'unknown',
      matched_signature: threatData.matched_signature || 'unknown',
      mitigation: threatData.mitigation || 'Monitor and investigate'
    })
  });
}

/**
 * Check if Ollama is running locally
 */
export async function checkOllamaStatus() {
  return request(OPS_BASE, '/ollama/status', {
    method: 'GET'
  });
}

/**
 * Run a test translation with a sample threat
 */
export async function testOllamaTranslation() {
  return request(OPS_BASE, '/ollama/test', {
    method: 'POST',
    body: JSON.stringify({})
  });
}
export const analyzeTraffic = (traffic) => opsRequest('/traffic/analyze', { method: 'POST', body: JSON.stringify({ traffic }) });
export const discoverAssets = () => opsRequest('/assets/discover', { method: 'POST' });
export const setBaselineAssets = (assets) => opsRequest('/assets/baseline', { method: 'POST', body: JSON.stringify({ baseline_assets: assets }) });
export const detectRogueAssets = () => opsRequest('/assets/rogue');
export const getAssetsStatus = () => opsRequest('/assets/status');

// ─── Layer 1 → Layer 2: AI Analysis Endpoint ────────────────────────────────
// Sends user input to Flask /api/analyze which passes it to the IDS engine.
//
// analyzeInput  — text / log / hint (JSON body)
// analyzeFile   — uploaded log file or binary .pcap (multipart)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Analyse a text snippet, log line, or IP via the IDS engine.
 * @param {object} opts
 * @param {string}   opts.text         Raw text or log line to analyse
 * @param {string[]} [opts.log_lines]  Multiple log lines
 * @param {string}   [opts.threat_type] Optional type hint
 * @param {string}   [opts.source_ip]  Source IP address
 * @param {number[]} [opts.target_ports] Destination ports
 */
export async function analyzeInput({ text = '', log_lines = [], threat_type = '', source_ip = '', target_ports = [] } = {}) {
  const OPS_ANALYZE = isLocal ? 'http://localhost:5000/api/analyze' : '/api/analyze';
  const res = await fetch(OPS_ANALYZE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, log_lines, threat_type, source_ip, target_ports }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Analysis failed: ${res.status}`);
  }
  return res.json();
}

/**
 * Analyse an uploaded log file or binary .pcap via the IDS engine.
 * @param {File}   file        The File object from <input type="file">
 * @param {string} [source_ip] Optional source IP hint
 */
export async function analyzeFile(file, source_ip = '') {
  const OPS_ANALYZE = isLocal ? 'http://localhost:5000/api/analyze' : '/api/analyze';
  const form = new FormData();
  form.append('file', file);
  if (source_ip) form.append('source_ip', source_ip);

  const res = await fetch(OPS_ANALYZE, { method: 'POST', body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `File analysis failed: ${res.status}`);
  }
  return res.json();
}

// ─── Layer 1 → Layer 2: Packet Scan Endpoints ────────────────────────────────

export async function startScan(packetCount = 200, continuous = false) {
  const url = `${OPS_BASE}/scan/start`;
  const body = continuous
    ? { packet_count: packetCount, continuous: true }
    : { packet_count: packetCount };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Failed to start scan: ${res.status}`);
  }
  return res.json();
}

export async function getScanStatus(job_id) {
  const url = job_id ? `${OPS_BASE}/scan/status/${job_id}` : `${OPS_BASE}/scan/status`;
  try {
    const res = await fetch(url, { method: 'GET', headers: { 'Content-Type': 'application/json' } });
    if (!res.ok) return { status: 'idle', progress: 0, phase: 'starting' };
    return await res.json();
  } catch (err) {
    console.warn('Scan status check failed:', err);
    return { status: 'idle', progress: 0, phase: 'starting' };
  }
}

/**
 * Best-effort stop signal to the Flask backend.
 * The backend may not implement /api/scan/stop yet — callers should catch errors.
 */
export async function stopScan(job_id = null) {
  const url = `${OPS_BASE}/scan/stop`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(job_id ? { job_id } : {}),
  });
  if (!res.ok) throw new Error(`Stop request failed: ${res.status}`);
  return res.json();
}