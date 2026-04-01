// ─── CyberMind API Service Layer ────────────────────────────────────────────

const BASE = '/api';

function getToken() {
  return localStorage.getItem('cybermind_token');
}

export function setToken(token) {
  localStorage.setItem('cybermind_token', token);
}

export function clearToken() {
  localStorage.removeItem('cybermind_token');
}

async function request(path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('auth:expired'));
    throw new Error('Session expired');
  }

  if (!res.ok) throw new Error(`API Error: ${res.status}`);
  return res.json();
}

// Auth
export const register = (username, email, password, confirmPassword, name, company) =>
  request('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password, confirmPassword, name, company }) });
export const verifyEmail = (token) =>
  request('/auth/verify-email', { method: 'POST', body: JSON.stringify({ token }) });
export const login = (username, password) =>
  request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
export const verifyAuth = () => request('/auth/verify');
export const logout = () => request('/auth/logout', { method: 'POST' });
export const forgotPassword = (email) =>
  request('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) });
export const resetPassword = (email, resetCode, newPassword, confirmPassword) =>
  request('/auth/reset-password', { method: 'POST', body: JSON.stringify({ email, resetCode, newPassword, confirmPassword }) });
export const getProfile = () => request('/auth/profile');
export const updateProfile = (data) =>
  request('/auth/profile', { method: 'PUT', body: JSON.stringify(data) });
export const changePassword = (currentPassword, newPassword, confirmPassword) =>
  request('/auth/change-password', { method: 'PUT', body: JSON.stringify({ currentPassword, newPassword, confirmPassword }) });

// Admin
export const getUsers = () => request('/admin/users');
export const getUser = (id) => request(`/admin/users/${id}`);
export const deleteUser = (id) => request(`/admin/users/${id}`, { method: 'DELETE' });
export const makeUserAdmin = (id) => request(`/admin/users/${id}/make-admin`, { method: 'PUT' });
export const removeUserAdmin = (id) => request(`/admin/users/${id}/remove-admin`, { method: 'PUT' });
export const getLoginActivity = () => request('/admin/login-activity');
export const getUserLoginActivity = (username) => request(`/admin/login-activity/user/${username}`);
export const resetUserPassword = (id) => request(`/admin/users/${id}/reset-password`, { method: 'POST' });

// Sessions
export const getSessions = () => request('/sessions');
export const logoutSession = (sessionId) => request(`/sessions/${sessionId}`, { method: 'DELETE' });
export const logoutOtherSessions = () => request('/sessions/logout-others', { method: 'POST' });

// Status
export const getStatus = () => request('/status');

// Devices
export const getDevices = () => request('/devices');
export const getDevice = (id) => request(`/devices/${id}`);
export const addDevice = (data) => request('/devices', { method: 'POST', body: JSON.stringify(data) });
export const updateDevice = (id, data) => request(`/devices/${id}`, { method: 'PUT', body: JSON.stringify(data) });
export const toggleDevice = (id) => request(`/devices/${id}/toggle`, { method: 'PATCH' });
export const deleteDevice = (id) => request(`/devices/${id}`, { method: 'DELETE' });

// Logs
export const getLogs = () => request('/logs');
export const addLog = (data) => request('/logs', { method: 'POST', body: JSON.stringify(data) });
export const deleteLog = (id) => request(`/logs/${id}`, { method: 'DELETE' });

// Honeypot
export const getHoneypot = () => request('/honeypot');
export const deployDecoy = (name) => request('/honeypot/deploy', { method: 'POST', body: JSON.stringify({ name }) });
export const triggerHoneypot = () => request('/honeypot/trigger', { method: 'POST' });

// Phishing
export const checkPhishing = (url) => request('/phishing/check', { method: 'POST', body: JSON.stringify({ url }) });

// Threats
export const getThreats = () => request('/threats');
export const getThreat = (id) => request(`/threats/${id}`);

// Kill Switch
export const activateKillSwitch = (deviceId) => request('/killswitch', { method: 'POST', body: JSON.stringify({ deviceId }) });

// Remediation
export const runRemediation = (playbook) => request('/remediation', { method: 'POST', body: JSON.stringify({ playbook }) });

// Log Translation
export const translateLog = (rawLog) => request('/logs/translate', { method: 'POST', body: JSON.stringify({ rawLog }) });

// Live Feed
export const getLiveFeed = () => request('/live-feed');

// Settings
export const getSettings = () => request('/settings');
export const updateSettings = (data) => request('/settings', { method: 'PUT', body: JSON.stringify(data) });

// Scan
export const runScan = () => request('/scan', { method: 'POST' });

// Alert Config
export const getAlertConfig = () => request('/alerts/config');
export const updateAlertConfig = (data) => request('/alerts/config', { method: 'PUT', body: JSON.stringify(data) });
