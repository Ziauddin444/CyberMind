// ─── CyberMind Sentinel — Main Application ─────────────────────────────────

import * as api from './api.js';

let currentScreen = 'dashboard';
let editingDevice = null;
let deletingDevice = null;
let lastLiveFeedText = '';
const seenBlockedRecordIds = new Set();
const seenNotificationEventKeys = new Set();
const seenLiveEventKeys = new Set();
let mockAttackCursor = 0;
let blockedIpsRefreshStarted = false;


const MOCK_ATTACK_SCENARIOS = [
  { attack: 'SYN flood attempt', ip: '45.83.122.41', type: 'warning' },
  { attack: 'UDP amplification probe', ip: '103.92.24.11', type: 'warning' },
  { attack: 'ICMP sweep reconnaissance', ip: '185.220.101.7', type: 'info' },
  { attack: 'Nmap stealth scan', ip: '91.134.77.192', type: 'warning' },
  { attack: 'Masscan high-rate sweep', ip: '146.70.18.63', type: 'warning' },
  { attack: 'SSH brute-force sequence', ip: '139.59.112.33', type: 'warning' },
  { attack: 'RDP credential stuffing', ip: '198.44.136.12', type: 'warning' },
  { attack: 'SMB null-session enumeration', ip: '172.105.58.20', type: 'info' },
  { attack: 'DNS tunneling signature', ip: '154.53.37.89', type: 'warning' },
  { attack: 'SQL injection payload burst', ip: '217.138.221.15', type: 'warning' },
  { attack: 'XSS reflected payload test', ip: '84.17.39.227', type: 'info' },
  { attack: 'Directory traversal exploit attempt', ip: '212.102.54.101', type: 'warning' },
  { attack: 'Command injection probe', ip: '95.214.53.18', type: 'warning' },
  { attack: 'Local file inclusion pattern', ip: '37.120.145.220', type: 'info' },
  { attack: 'Web shell upload attempt', ip: '46.165.245.71', type: 'warning' },
  { attack: 'C2 beacon callback blocked', ip: '45.67.231.10', type: 'warning' },
  { attack: 'Reverse shell handshake denied', ip: '66.115.189.211', type: 'warning' },
  { attack: 'PowerShell encoded command detected', ip: '89.44.9.176', type: 'warning' },
  { attack: 'Mimikatz credential dump pattern', ip: '107.189.29.8', type: 'warning' },
  { attack: 'Kerberoasting enumeration traffic', ip: '104.244.72.221', type: 'info' },
  { attack: 'ARP spoofing frame anomaly', ip: '51.15.129.52', type: 'warning' },
  { attack: 'Rogue DHCP offer rejected', ip: '176.10.99.200', type: 'warning' },
  { attack: 'FTP anonymous write attempt', ip: '80.67.172.162', type: 'info' },
  { attack: 'Telnet brute-force on legacy host', ip: '5.199.130.188', type: 'warning' },
  { attack: 'LDAP enumeration burst', ip: '138.197.204.45', type: 'info' },
  { attack: 'SNMP community string guessing', ip: '77.247.181.165', type: 'warning' },
  { attack: 'Token replay signature blocked', ip: '23.146.248.90', type: 'warning' },
  { attack: 'Malware staging URL callback', ip: '185.220.102.244', type: 'warning' },
  { attack: 'Data exfiltration over HTTPS pattern', ip: '143.244.35.61', type: 'warning' },
  { attack: 'Privilege escalation exploit chain', ip: '31.7.58.114', type: 'warning' },
];

function getSavedTheme() {
  return localStorage.getItem('cybermind_theme') || 'light';
}

function applyTheme(theme) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  document.body.classList.toggle('light-theme', nextTheme === 'light');
  document.body.classList.toggle('dark-theme', nextTheme === 'dark');
  localStorage.setItem('cybermind_theme', nextTheme);

  const icon = document.getElementById('theme-toggle-icon');
  const button = document.getElementById('theme-toggle-btn');
  if (icon) {
    icon.className = nextTheme === 'dark' ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
  }
  if (button) {
    const label = nextTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
    button.setAttribute('aria-label', label);
    button.title = label;
  }
}



function toggleTheme() {
  applyTheme(getSavedTheme() === 'light' ? 'dark' : 'light');
}

// ─── Toast ──────────────────────────────────────────────────────────────────

function showToast(message) {
  const toast = document.getElementById('toast');
  const toastText = document.getElementById('toast-text');
  toastText.innerText = message;
  toast.classList.remove('hidden');
  toast.style.transform = 'translateY(30px)';
  toast.style.opacity = 0;
  setTimeout(() => { toast.style.transform = 'translateY(0)'; toast.style.opacity = 1; }, 10);
  setTimeout(() => { toast.style.opacity = 0; setTimeout(() => toast.classList.add('hidden'), 300); }, 2800);
}

function notifyOnce(eventKey, message) {
  if (!eventKey) {
    showToast(message);
    return;
  }

  if (seenNotificationEventKeys.has(eventKey)) return;
  seenNotificationEventKeys.add(eventKey);
  showToast(message);
}

function toOwnerFriendlyText(text, type = 'info') {
  if (!text) return '';

  const normalized = String(text).trim();
  const lowered = normalized.toLowerCase();

  if (lowered.includes('port scan detected')) {
    return 'Someone from outside scanned your network. We blocked them.';
  }
  if (lowered.includes('outbound connection to suspicious domain blocked')) {
    return 'A device tried to connect to an unsafe website. We blocked that connection.';
  }
  if (lowered.includes('firewall rules updated automatically')) {
    return 'Your security protections were updated automatically.';
  }
  if (lowered.includes('ssl certificate renewal verified')) {
    return 'Your secure website connection settings were checked and are valid.';
  }
  if (lowered.includes('new login from trusted device')) {
    return 'A known device signed in successfully.';
  }
  if (lowered.includes('scheduled backup completed successfully')) {
    return 'Your scheduled backup finished successfully.';
  }
  if (lowered.includes('blocked suspicious ip')) {
    return normalized.replace('Blocked suspicious IP', 'We blocked a risky connection from');
  }
  if (lowered.includes('block attempt failed')) {
    return normalized.replace('Block attempt failed', 'We tried to block a risky connection, but it failed for');
  }

  return type === 'warning' ? `Security warning: ${normalized}` : normalized;
}

// ─── Auth Flow ──────────────────────────────────────────────────────────────

async function checkAuth() {
  try {
    const result = await api.verifyAuth();
    if (result.valid) {
      api.setUserContext(result.user);
      showApp(result.user);
      return true;
    }
  } catch (_) { /* not authed */ }
  showLogin();
  return false;
}

function showLogin() {
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('app-container').classList.add('hidden');
}

function showApp(user) {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app-container').classList.remove('hidden');

  if (user) {
    const avatarEl = document.getElementById('user-avatar');
    if (avatarEl) avatarEl.textContent = user.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);

    const role = user.role || (user.isAdmin ? 'admin' : 'viewer');
    const canAccessAdmin = role === 'admin' || role === 'super-admin';

    // Show admin link if user has admin-level role
    if (canAccessAdmin) {
      document.getElementById('admin-nav-link')?.classList.remove('hidden');
    } else {
      document.getElementById('admin-nav-link')?.classList.add('hidden');
    }
  }

  loadDashboard();
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errorEl = document.getElementById('login-error');
  const errorText = document.getElementById('login-error-text');
  const btn = document.getElementById('login-btn');

  if (!username || !password) {
    errorEl.classList.remove('hidden');
    errorText.textContent = 'Please enter username and password';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>SIGNING IN...';

  try {
    const result = await api.login(username, password);
    api.setToken(result.token, result.user);
    errorEl.classList.add('hidden');
    showApp(result.user);
  } catch (err) {
    errorEl.classList.remove('hidden');
    if (String(err.message || '').includes('403')) {
      errorText.textContent = 'Access denied for your role';
    } else if (String(err.message || '').includes('429')) {
      errorText.textContent = 'Too many failed attempts. Try again later.';
    } else {
      errorText.textContent = 'Invalid username or password';
    }
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-right-to-bracket mr-2"></i>SIGN IN';
  }
}

async function handleLogout() {
  try { await api.logout(); } catch (_) { /* ignore */ }
  api.clearToken();
  showLogin();
  clearAuthForms();
  showToast('Signed out successfully');
}

function switchAuthTab(tab) {
  const loginForm = document.getElementById('login-form');
  const signupForm = document.getElementById('signup-form');
  const loginTab = document.getElementById('login-tab');
  const signupTab = document.getElementById('signup-tab');

  if (tab === 'login') {
    loginForm.classList.remove('hidden');
    signupForm.classList.add('hidden');
    loginTab.classList.add('active', 'border-b-2', 'border-yellow-400', 'text-white');
    loginTab.classList.remove('border-transparent', 'text-zinc-500');
    signupTab.classList.remove('active', 'border-b-2', 'border-yellow-400', 'text-white');
    signupTab.classList.add('border-transparent', 'text-zinc-500');
  } else {
    loginForm.classList.add('hidden');
    signupForm.classList.remove('hidden');
    signupTab.classList.add('active', 'border-b-2', 'border-yellow-400', 'text-white');
    signupTab.classList.remove('border-transparent', 'text-zinc-500');
    loginTab.classList.remove('active', 'border-b-2', 'border-yellow-400', 'text-white');
    loginTab.classList.add('border-transparent', 'text-zinc-500');
  }
}

function clearAuthForms() {
  document.getElementById('login-form')?.reset();
  document.getElementById('signup-form')?.reset();
}

async function handleSignup(e) {
  e.preventDefault();
  const name = document.getElementById('signup-name').value.trim();
  const username = document.getElementById('signup-username').value.trim();
  const email = document.getElementById('signup-email').value.trim();
  const company = document.getElementById('signup-company').value.trim();
  const password = document.getElementById('signup-password').value;
  const confirmPassword = document.getElementById('signup-confirm-password').value;
  const errorEl = document.getElementById('signup-error');
  const errorText = document.getElementById('signup-error-text');
  const btn = document.getElementById('signup-btn');

  if (!name || !username || !email || !password || !confirmPassword) {
    errorEl.classList.remove('hidden');
    errorText.textContent = 'Please fill in all fields';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>CREATING ACCOUNT...';

  try {
    const result = await api.register(username, email, password, confirmPassword, name, company);
    errorEl.classList.add('hidden');
    showToast('Account created! Verify your email to login...');

    // Store email token for verification
    sessionStorage.setItem('emailToken', result.emailToken);
    sessionStorage.setItem('userEmail', email);

    // Switch to email verification form
    setTimeout(() => {
      clearAuthForms();
      switchAuthFlow('verify-email');
    }, 1000);
  } catch (err) {
    errorEl.classList.remove('hidden');
    errorText.textContent = err.message.includes('Username already')
      ? 'Username already exists'
      : err.message.includes('Email already')
        ? 'Email already registered'
        : err.message.includes('Passwords do not match')
          ? 'Passwords do not match'
          : err.message.includes('at least 6')
            ? 'Password must be at least 6 characters'
            : 'Registration failed. Please try again.';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-check mr-2"></i>CREATE ACCOUNT';
  }
}

// ─── Password Reset Flow ────────────────────────────────────────────────────

function switchAuthFlow(flow) {
  const loginForm = document.getElementById('login-form');
  const forgotForm = document.getElementById('forgot-password-form');
  const resetForm = document.getElementById('reset-password-form');
  const verifyForm = document.getElementById('email-verification-form');

  loginForm.classList.add('hidden');
  forgotForm.classList.add('hidden');
  resetForm.classList.add('hidden');
  verifyForm.classList.add('hidden');

  if (flow === 'login') loginForm.classList.remove('hidden');
  else if (flow === 'forgot') forgotForm.classList.remove('hidden');
  else if (flow === 'reset') resetForm.classList.remove('hidden');
  else if (flow === 'verify-email') verifyForm.classList.remove('hidden');
}

async function handleEmailVerification(e) {
  e.preventDefault();
  const code = document.getElementById('email-verification-code').value.trim();
  const errorEl = document.getElementById('email-verification-error');
  const btn = document.getElementById('email-verification-btn-submit');

  if (!code) {
    errorEl.classList.remove('hidden');
    document.getElementById('email-verification-error-text').textContent = 'Please enter verification code';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>VERIFYING...';

  try {
    await api.verifyEmail(code);
    errorEl.classList.add('hidden');
    showToast('Email verified! You can now login.');

    // Clear and return to login
    setTimeout(() => {
      clearAuthForms();
      sessionStorage.removeItem('emailToken');
      sessionStorage.removeItem('userEmail');
      switchAuthFlow('login');
    }, 1500);
  } catch (err) {
    errorEl.classList.remove('hidden');
    document.getElementById('email-verification-error-text').textContent =
      err.message.includes('expired') ? 'Code expired. Request a new one.' :
        err.message.includes('Invalid') ? 'Invalid verification code' :
          'Verification failed. Please try again.';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-check mr-2"></i>VERIFY EMAIL';
  }
}

async function handleForgotPassword(e) {
  e.preventDefault();
  const email = document.getElementById('forgot-email').value.trim();
  const errorEl = document.getElementById('forgot-password-error');
  const successEl = document.getElementById('forgot-password-success');
  const btn = document.getElementById('forgot-password-btn-submit');

  if (!email) {
    errorEl.classList.remove('hidden');
    document.getElementById('forgot-password-error-text').textContent = 'Please enter your email';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>SENDING...';

  try {
    const result = await api.forgotPassword(email);
    errorEl.classList.add('hidden');
    successEl.classList.remove('hidden');
    document.getElementById('forgot-password-success-text').textContent = `Reset code: ${result.resetCode} (valid for 15 min)`;

    // Store email and reset code for next step
    sessionStorage.setItem('resetEmail', email);
    sessionStorage.setItem('resetCode', result.resetCode);

    setTimeout(() => switchAuthFlow('reset'), 2000);
  } catch (err) {
    errorEl.classList.remove('hidden');
    document.getElementById('forgot-password-error-text').textContent =
      err.message.includes('not found') ? 'Email not found' : 'Failed to send reset code. Please try again.';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-paper-plane mr-2"></i>SEND RESET CODE';
  }
}

async function handleResetPassword(e) {
  e.preventDefault();
  const email = sessionStorage.getItem('resetEmail');
  const resetCode = document.getElementById('reset-code').value.trim();
  const newPassword = document.getElementById('reset-new-password').value;
  const confirmPassword = document.getElementById('reset-confirm-password').value;
  const errorEl = document.getElementById('reset-password-error');
  const btn = document.getElementById('reset-password-btn-submit');

  if (!resetCode || !newPassword || !confirmPassword) {
    errorEl.classList.remove('hidden');
    document.getElementById('reset-password-error-text').textContent = 'Please fill in all fields';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>RESETTING...';

  try {
    await api.resetPassword(email, resetCode, newPassword, confirmPassword);
    errorEl.classList.add('hidden');
    showToast('Password reset successfully! Returning to login...');

    // Clear forms and return to login
    setTimeout(() => {
      clearAuthForms();
      sessionStorage.removeItem('resetEmail');
      sessionStorage.removeItem('resetCode');
      switchAuthFlow('login');
    }, 1500);
  } catch (err) {
    errorEl.classList.remove('hidden');
    document.getElementById('reset-password-error-text').textContent =
      err.message.includes('expired') ? 'Reset code expired. Request a new one.' :
        err.message.includes('Invalid') ? 'Invalid reset code' :
          err.message.includes('do not match') ? 'Passwords do not match' :
            err.message.includes('at least 6') ? 'Password must be at least 6 characters' :
              'Password reset failed. Please try again.';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-check mr-2"></i>RESET PASSWORD';
  }
}

// ─── Profile Management ────────────────────────────────────────────────────

async function loadUserProfile() {
  try {
    const user = await api.getProfile();
    document.getElementById('profile-name').value = user.name || '';
    document.getElementById('profile-email').value = user.email || '';
    document.getElementById('profile-company').value = user.company || '';
    document.getElementById('profile-username').value = user.username || '';
  } catch (err) {
    showToast('Failed to load profile');
  }
}

async function handleUpdateProfile() {
  const name = document.getElementById('profile-name').value.trim();
  const email = document.getElementById('profile-email').value.trim();
  const company = document.getElementById('profile-company').value.trim();
  const errorEl = document.getElementById('profile-update-error');
  const successEl = document.getElementById('profile-update-success');

  if (!name || !email || !company) {
    errorEl.classList.remove('hidden');
    document.getElementById('profile-update-error-text').textContent = 'Please fill in all fields';
    return;
  }

  try {
    await api.updateProfile({ name, email, company });
    errorEl.classList.add('hidden');
    successEl.classList.remove('hidden');
    setTimeout(() => successEl.classList.add('hidden'), 3000);
    showToast('Profile updated successfully');
  } catch (err) {
    errorEl.classList.remove('hidden');
    document.getElementById('profile-update-error-text').textContent =
      err.message.includes('already') ? 'Email already in use' : 'Failed to update profile';
  }
}

async function handleChangePassword() {
  const currentPassword = document.getElementById('change-password-current').value;
  const newPassword = document.getElementById('change-password-new').value;
  const confirmPassword = document.getElementById('change-password-confirm').value;
  const errorEl = document.getElementById('password-change-error');
  const successEl = document.getElementById('password-change-success');

  if (!currentPassword || !newPassword || !confirmPassword) {
    errorEl.classList.remove('hidden');
    document.getElementById('password-change-error-text').textContent = 'Please fill in all fields';
    return;
  }

  try {
    await api.changePassword(currentPassword, newPassword, confirmPassword);
    errorEl.classList.add('hidden');
    successEl.classList.remove('hidden');

    // Clear the form
    document.getElementById('change-password-current').value = '';
    document.getElementById('change-password-new').value = '';
    document.getElementById('change-password-confirm').value = '';

    setTimeout(() => successEl.classList.add('hidden'), 3000);
    showToast('Password changed successfully');
  } catch (err) {
    errorEl.classList.remove('hidden');
    document.getElementById('password-change-error-text').textContent =
      err.message.includes('incorrect') ? 'Current password is incorrect' :
        err.message.includes('do not match') ? 'New passwords do not match' :
          err.message.includes('at least 6') ? 'Password must be at least 6 characters' :
            'Failed to change password';
  }
}

// ─── Admin Panel Functions ──────────────────────────────────────────────────

async function loadAdminUsers() {
  try {
    const users = await api.getUsers();
    const tbody = document.getElementById('admin-users-list');
    tbody.innerHTML = '';

    users.forEach(user => {
      const row = document.createElement('tr');
      const createdDate = new Date(user.createdAt).toLocaleDateString();

      row.innerHTML = `
        <td class="px-6 py-4 text-zinc-300">${user.username}</td>
        <td class="px-6 py-4 text-zinc-400 text-sm">${user.email}</td>
        <td class="px-6 py-4 text-zinc-300">${user.name || '-'}</td>
        <td class="px-6 py-4">
          <span class="inline-block px-3 py-1 rounded-full text-xs font-medium ${user.isAdmin ? 'bg-yellow-400/10 text-yellow-400' : 'bg-zinc-800 text-zinc-400'
        }">
            ${user.isAdmin ? 'Admin' : 'User'}
          </span>
        </td>
        <td class="px-6 py-4 text-zinc-400">${user.loginCount || 0}</td>
        <td class="px-6 py-4">
          <span class="inline-block px-3 py-1 rounded-full text-xs font-medium ${user.emailVerified ? 'bg-emerald-400/10 text-emerald-400' : 'bg-red-400/10 text-red-400'
        }">
            ${user.emailVerified ? '✓' : '✗'}
          </span>
        </td>
        <td class="px-6 py-4">
          <div class="flex gap-2">
            <button data-admin-action="reset-password" data-user-id="${user.id}" class="px-3 py-1 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 text-xs font-medium transition">
              Reset
            </button>
            ${user.isAdmin ? `
              <button data-admin-action="remove-admin" data-user-id="${user.id}" class="px-3 py-1 rounded-lg bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 text-xs font-medium transition">
                Demote
              </button>
            ` : `
              <button data-admin-action="make-admin" data-user-id="${user.id}" class="px-3 py-1 rounded-lg bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20 text-xs font-medium transition">
                Promote
              </button>
            `}
            <button data-admin-action="delete-user" data-user-id="${user.id}" class="px-3 py-1 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 text-xs font-medium transition">
              Delete
            </button>
          </div>
        </td>
      `;

      tbody.appendChild(row);
    });
  } catch (err) {
    showToast('Failed to load users: ' + err.message);
  }
}

async function loadAdminActivity() {
  try {
    const activity = await api.getLoginActivity();
    const container = document.getElementById('admin-activity-list');
    container.innerHTML = '';

    if (activity.length === 0) {
      container.innerHTML = '<div class="text-center py-8 text-zinc-400">No login activity recorded</div>';
      return;
    }

    activity.slice(0, 100).forEach(entry => {
      const date = new Date(entry.timestamp);
      const dateStr = date.toLocaleDateString();
      const timeStr = date.toLocaleTimeString();

      const item = document.createElement('div');
      item.className = 'bg-zinc-800 rounded-lg p-4 border-l-4 ' +
        (entry.success ? 'border-emerald-400' : 'border-red-400');

      item.innerHTML = `
        <div class="flex justify-between items-start">
          <div>
            <div class="font-medium text-zinc-300">${entry.username}</div>
            <div class="text-sm text-zinc-400 mt-1">
              ${entry.success ? '<i class="fa-solid fa-check text-emerald-400"></i>' : '<i class="fa-solid fa-xmark text-red-400"></i>'}
              ${entry.success ? 'Successful login' : 'Failed login - ' + (entry.reason || 'Unknown')}
            </div>
            <div class="text-xs text-zinc-500 mt-2">
              <i class="fa-solid fa-globe mr-1"></i>${entry.ip}
            </div>
          </div>
          <div class="text-right text-xs text-zinc-500">
            <div>${dateStr}</div>
            <div>${timeStr}</div>
          </div>
        </div>
      `;

      container.appendChild(item);
    });
  } catch (err) {
    showToast('Failed to load activity: ' + err.message);
  }
}

function switchAdminTab(tab) {
  // Update tab buttons
  document.querySelectorAll('.admin-tab').forEach(btn => {
    btn.classList.remove('border-yellow-400', 'text-white');
    btn.classList.add('border-transparent', 'text-zinc-400');
  });

  const activeTab = document.querySelector(`.admin-tab[data-admin-tab="${tab}"]`);
  if (activeTab) {
    activeTab.classList.add('border-yellow-400', 'text-white');
    activeTab.classList.remove('border-transparent', 'text-zinc-400');
  }

  // Show/hide content
  document.querySelectorAll('.admin-tab-content').forEach(content => {
    content.classList.add('hidden');
  });

  const contentEl = document.getElementById(`admin-${tab}-tab`);
  if (contentEl) contentEl.classList.remove('hidden');

  // Load data
  if (tab === 'users') loadAdminUsers();
  else if (tab === 'activity') loadAdminActivity();
}

// ─── Navigation ─────────────────────────────────────────────────────────────

function navigateTo(screen) {
  currentScreen = screen;
  const screens = ['dashboard-screen', 'logs-screen', 'honeypot-screen', 'threats-screen', 'settings-screen', 'admin-screen', 'analyze-screen'];
  screens.forEach(id => document.getElementById(id)?.classList.add('hidden'));

  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.remove('text-white');
    link.classList.add('text-zinc-400');
  });

  const navLink = document.querySelector(`[data-nav="${screen}"]`);
  if (navLink) { navLink.classList.remove('text-zinc-400'); navLink.classList.add('text-white'); }

  switch (screen) {
    case 'dashboard': document.getElementById('dashboard-screen').classList.remove('hidden'); loadDashboard(); break;
    case 'logs': document.getElementById('logs-screen').classList.remove('hidden'); loadLogs(); break;
    case 'honeypot': document.getElementById('honeypot-screen').classList.remove('hidden'); loadHoneypot(); break;
    case 'threats': document.getElementById('threats-screen').classList.remove('hidden'); loadThreats(); break;
    case 'settings': document.getElementById('settings-screen').classList.remove('hidden'); loadSettings(); break;
    case 'admin': document.getElementById('admin-screen').classList.remove('hidden'); switchAdminTab('users'); break;
    case 'analyze': document.getElementById('analyze-screen').classList.remove('hidden'); initAnalyzeScreen(); break;
    case 'phish': navigateTo('dashboard'); setTimeout(() => switchTab(1), 100); break;
  }
}

// ─── Analyze Screen ────────────────────────────────────────────────────────────────────
// Layer 1 of the 3-layer architecture.
// Sends user input to Flask /api/analyze via fetch (no page reload).
// ──────────────────────────────────────────────────────────────────────────────

let _analyzeScreenReady = false; // wire events only once

function initAnalyzeScreen() {
  if (_analyzeScreenReady) return;
  _analyzeScreenReady = true;

  // File picker label
  document.getElementById('analyze-file-input').addEventListener('change', function () {
    const label = document.getElementById('analyze-file-label');
    label.textContent = this.files[0]?.name || 'Choose file…';
  });

  // Form submit
  document.getElementById('analyze-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    await runAnalysis();
  });

  // Wire the Scan panel (Start Scan button + slider)
  initScanPanel();
}

// Severity colour map
const _SEV_STYLE = {
  critical: { header: 'bg-red-950/80 border-red-600', icon: 'bg-red-500/20 text-red-400', badge: 'bg-red-500 text-white' },
  high: { header: 'bg-orange-950/80 border-orange-500', icon: 'bg-orange-500/20 text-orange-400', badge: 'bg-orange-500 text-white' },
  medium: { header: 'bg-yellow-950/60 border-yellow-600', icon: 'bg-yellow-500/20 text-yellow-400', badge: 'bg-yellow-500 text-black' },
  low: { header: 'bg-zinc-900/80 border-zinc-600', icon: 'bg-zinc-700/50 text-zinc-300', badge: 'bg-zinc-600 text-white' },
};

async function runAnalysis() {
  const textInput = document.getElementById('analyze-text-input').value.trim();
  const ipInput = document.getElementById('analyze-ip-input').value.trim();
  const fileInput = document.getElementById('analyze-file-input');
  const resultCard = document.getElementById('analyze-result-card');
  const errorDiv = document.getElementById('analyze-error');
  const btn = document.getElementById('analyze-submit-btn');
  const btnIcon = document.getElementById('analyze-btn-icon');
  const btnLabel = document.getElementById('analyze-btn-label');

  // Reset state
  resultCard.classList.add('hidden');
  errorDiv.classList.add('hidden');

  // Require at least text or a file
  if (!textInput && !fileInput.files[0]) {
    document.getElementById('analyze-error-text').textContent =
      'Please enter a log line or upload a file before analyzing.';
    errorDiv.classList.remove('hidden');
    return;
  }

  // Loading state
  btn.disabled = true;
  btnIcon.className = 'fa-solid fa-spinner fa-spin';
  btnLabel.textContent = 'Analyzing…';

  try {
    let result;

    if (fileInput.files[0]) {
      // ─ File upload path (multipart) ─────────────────────────────────────
      const { analyzeFile } = await import('./api.js');
      result = await analyzeFile(fileInput.files[0], ipInput);
    } else {
      // ─ JSON text path ────────────────────────────────────────────────
      const { analyzeInput } = await import('./api.js');
      result = await analyzeInput({ text: textInput, source_ip: ipInput });
    }

    renderAnalysisResult(result);

  } catch (err) {
    document.getElementById('analyze-error-text').textContent =
      err.message || 'Analysis failed. Make sure the Flask backend is running on port 5000.';
    errorDiv.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btnIcon.className = 'fa-solid fa-magnifying-glass';
    btnLabel.textContent = 'Analyze with CyberMind IDS';
  }
}

function renderAnalysisResult(result) {
  const card = document.getElementById('analyze-result-card');
  const sev = (result.severity || 'low').toLowerCase();
  const style = _SEV_STYLE[sev] || _SEV_STYLE.low;

  // ─ Header colours ────────────────────────────────────────────────────────
  const header = document.getElementById('analyze-result-header');
  header.className = `flex items-center gap-4 rounded-t-2xl border border-b-0 px-6 py-4 ${style.header}`;

  const iconWrap = document.getElementById('analyze-result-icon');
  iconWrap.className = `w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0 ${style.icon}`;

  // ─ Badges ──────────────────────────────────────────────────────────────────
  const sevBadge = document.getElementById('analyze-result-severity-badge');
  sevBadge.textContent = sev.toUpperCase();
  sevBadge.className = `px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${style.badge}`;

  document.getElementById('analyze-result-type-badge').textContent =
    (result.threat_type || 'unknown').replace(/_/g, ' ').toUpperCase();

  const confidence = Math.round((result.confidence || 0) * 100);
  document.getElementById('analyze-result-confidence').textContent = `${confidence}% confidence`;

  document.getElementById('analyze-result-label').textContent =
    result.label || (result.threat_detected ? 'Threat Detected' : 'No Threat Found');

  // ─ Summary ───────────────────────────────────────────────────────────────────
  document.getElementById('analyze-result-summary').textContent = result.summary || '';

  // ─ Signature matches ──────────────────────────────────────────────────────────
  const matchSection = document.getElementById('analyze-matches-section');
  const matchList = document.getElementById('analyze-matches-list');
  const matches = result.matches || [];
  matchList.innerHTML = '';

  if (matches.length > 0) {
    matchSection.classList.remove('hidden');
    matches.slice(0, 8).forEach((m) => {
      const ms = _SEV_STYLE[(m.severity || 'low').toLowerCase()] || _SEV_STYLE.low;
      const chip = document.createElement('div');
      chip.className = 'flex items-center gap-2 text-xs py-1.5 px-3 rounded-lg bg-zinc-800/60 border border-zinc-700';
      chip.innerHTML = `
        <span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase ${ms.badge}">${(m.severity || '?').toUpperCase()}</span>
        <span class="font-semibold text-zinc-200">${m.label || m.attack_type || ''}</span>
        <span class="text-zinc-500 ml-auto font-mono">${Math.round((m.confidence || 0) * 100)}%</span>
      `;
      matchList.appendChild(chip);
    });
  } else {
    matchSection.classList.add('hidden');
  }

  // ─ Recommendations ───────────────────────────────────────────────────────────
  const recList = document.getElementById('analyze-recommendations-list');
  recList.innerHTML = '';
  (result.recommendations || []).forEach((rec) => {
    const li = document.createElement('li');
    li.className = 'flex items-start gap-2';
    li.innerHTML = `<i class="fa-solid fa-circle-right text-yellow-400 mt-0.5 flex-shrink-0 text-xs"></i><span>${rec}</span>`;
    recList.appendChild(li);
  });

  // ─ Meta ────────────────────────────────────────────────────────────────────────
  document.getElementById('analyze-result-model').textContent = result.model || '—';
  document.getElementById('analyze-result-fp').textContent = result.fingerprint || '—';
  document.getElementById('analyze-result-ts').textContent = result.timestamp
    ? new Date(result.timestamp).toLocaleTimeString() : '—';

  // ─ Reveal card ───────────────────────────────────────────────────────────────────
  card.classList.remove('hidden');
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function toggleMobileMenu() {
  document.getElementById('mobile-menu').classList.toggle('hidden');
}

// ─── Network Scan Handler ────────────────────────────────────────────────────

let _scanPanelReady = false;
let _currentScanPollTimer = null;

function initScanPanel() {
  if (_scanPanelReady) return;
  _scanPanelReady = true;
  const slider = document.getElementById('scan-packet-count');
  const label  = document.getElementById('scan-packet-count-label');
  if (slider && label) slider.addEventListener('input', () => { label.textContent = slider.value; });
  const btn = document.getElementById('scan-start-btn');
  if (btn) btn.addEventListener('click', runScan);
}

const _SCAN_PHASE_LABELS = {
  starting:    'Initialising scanner...',
  capturing:   'Capturing packets with Scapy...',
  classifying: 'Running Random Forest classifier...',
  done:        'Analysis complete',
  error:       'Error',
};

function _scanLog(msg) {
  const term = document.getElementById('scan-terminal');
  if (!term) return;
  const line = document.createElement('div');
  line.textContent = `> ${msg}`;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function _setScanProgress(pct, phase) {
  const bar   = document.getElementById('scan-progress-bar');
  const label = document.getElementById('scan-phase-label');
  const pctEl = document.getElementById('scan-progress-pct');
  if (bar)   bar.style.width = `${pct}%`;
  if (label) label.textContent = _SCAN_PHASE_LABELS[phase] || phase;
  if (pctEl) pctEl.textContent = `${pct}%`;
}

async function runScan() {
  const slider      = document.getElementById('scan-packet-count');
  const packetCount = slider ? parseInt(slider.value) : 100;
  const btn         = document.getElementById('scan-start-btn');
  const btnIcon     = document.getElementById('scan-btn-icon');
  const btnLabel    = document.getElementById('scan-btn-label');
  const progPanel   = document.getElementById('scan-progress-panel');
  const resultCard  = document.getElementById('scan-result-card');
  const errDiv      = document.getElementById('scan-error');
  const term        = document.getElementById('scan-terminal');

  // Reset UI
  if (resultCard) resultCard.classList.add('hidden');
  if (errDiv)     errDiv.classList.add('hidden');
  if (term)       term.innerHTML = '<div class="text-yellow-400">$ cybermind-ids --scan --model random_forest</div>';
  _setScanProgress(0, 'starting');
  if (progPanel)  progPanel.classList.remove('hidden');
  if (btn) btn.disabled = true;
  if (btnIcon) btnIcon.className = 'fa-solid fa-spinner fa-spin text-lg';
  if (btnLabel) btnLabel.textContent = 'SCANNING...';
  if (_currentScanPollTimer) clearInterval(_currentScanPollTimer);

  try {
    // Fire the scan — returns job_id immediately (no wait)
    const { startScan, getScanStatus } = await import('./api.js');
    _scanLog(`Starting scan: ${packetCount} packets`);
    const { job_id } = await startScan(packetCount);
    _scanLog(`Job ${job_id.slice(0, 8)}... launched`);
    _scanLog('Scapy listener active...');

    // Poll every 1 second — screen stays responsive via async/await
    await new Promise((resolve, reject) => {
      _currentScanPollTimer = setInterval(async () => {
        try {
          const s = await getScanStatus(job_id);
          _setScanProgress(s.progress || 0, s.phase);
          if (s.phase === 'classifying') _scanLog('Packets captured — running RF model...');
          if (s.status === 'done') {
            clearInterval(_currentScanPollTimer);
            _scanLog(`Label: ${s.result.label}  |  Confidence: ${Math.round(s.result.confidence * 100)}%`);
            renderScanResult(s.result);
            resolve();
          } else if (s.status === 'error') {
            clearInterval(_currentScanPollTimer);
            reject(new Error(s.error || 'Scan failed'));
          }
        } catch (e) { clearInterval(_currentScanPollTimer); reject(e); }
      }, 1000);
    });

  } catch (err) {
    _scanLog(`ERROR: ${err.message}`);
    const errText = document.getElementById('scan-error-text');
    if (errText) errText.textContent = err.message || 'Scan failed. Is Flask running on port 5000?';
    if (errDiv) errDiv.classList.remove('hidden');
  } finally {
    if (btn) btn.disabled = false;
    if (btnIcon) btnIcon.className = 'fa-solid fa-satellite-dish text-lg';
    if (btnLabel) btnLabel.textContent = 'START SCAN';
  }
}

const _SCAN_SEV = {
  critical: { header: 'bg-red-950/80 border-red-600',     icon: 'bg-red-500/20',     badge: 'bg-red-500 text-white' },
  medium:   { header: 'bg-orange-950/60 border-orange-500', icon: 'bg-orange-500/20', badge: 'bg-orange-400 text-black' },
  low:      { header: 'bg-zinc-900/80 border-zinc-600',   icon: 'bg-emerald-500/20', badge: 'bg-emerald-500 text-black' },
};
const _BAR_CLR = { safe:'bg-emerald-500', brute_force:'bg-red-500', port_scan:'bg-orange-400', ddos:'bg-rose-500', sql_injection:'bg-purple-500', malware_c2:'bg-yellow-500' };

function renderScanResult(result) {
  const card    = document.getElementById('scan-result-card');
  const sev     = result.severity || 'low';
  const style   = _SCAN_SEV[sev] || _SCAN_SEV.low;
  const confPct = Math.round((result.confidence || 0) * 100);

  const header = document.getElementById('scan-result-header');
  if (header) header.className = `flex items-center gap-5 px-6 py-5 border-b ${style.header}`;

  const icon = document.getElementById('scan-result-icon');
  if (icon) { icon.className = `w-14 h-14 rounded-full flex items-center justify-center flex-shrink-0 text-2xl ${style.icon}`; icon.textContent = result.threat_detected ? '🚨' : '✅'; }

  const vt = document.getElementById('scan-verdict-text');
  if (vt) vt.textContent = result.verdict || result.label_pretty || result.label;

  const sb = document.getElementById('scan-result-severity');
  if (sb) { sb.textContent = sev.toUpperCase(); sb.className = `px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${style.badge}`; }

  const cl = document.getElementById('scan-result-confidence-label');
  if (cl) cl.textContent = `${confPct}% confidence`;

  const ml = document.getElementById('scan-result-mode-label');
  if (ml) ml.textContent = result.capture_mode === 'live' ? '📡 live capture' : '🔬 simulated';

  const bc = document.getElementById('scan-big-conf');
  if (bc) bc.textContent = `${confPct}%`;

  const barsEl = document.getElementById('scan-breakdown-bars');
  if (barsEl && result.breakdown) {
    barsEl.innerHTML = '';
    Object.entries(result.breakdown).sort(([, a], [, b]) => b - a).forEach(([lbl, pct]) => {
      const clr = _BAR_CLR[lbl] || 'bg-zinc-500';
      const row = document.createElement('div');
      row.innerHTML = `<div class="flex items-center justify-between text-xs mb-1"><span class="text-zinc-300 font-medium">${lbl.replace(/_/g,' ')}</span><span class="text-zinc-500 font-mono">${pct.toFixed(1)}%</span></div><div class="w-full h-1.5 bg-zinc-800 rounded-full overflow-hidden"><div class="${clr} h-full rounded-full" style="width:${pct}%"></div></div>`;
      barsEl.appendChild(row);
    });
  }

  const mc = document.getElementById('scan-meta-count'); if (mc) mc.textContent = result.packet_count;
  const mm = document.getElementById('scan-meta-mode');  if (mm) mm.textContent = result.capture_mode || '--';
  const mt = document.getElementById('scan-meta-ts');    if (mt) mt.textContent = result.timestamp ? new Date(result.timestamp).toLocaleTimeString() : '--';

  if (card) { card.className = `rounded-2xl border overflow-hidden ${style.header}`; card.classList.remove('hidden'); card.scrollIntoView({ behavior:'smooth', block:'nearest' }); }
}

// ─── Tab Switching ──────────────────────────────────────────────────────────

function switchTab(tabIndex) {
  document.querySelectorAll('.tab-button').forEach((btn, i) => {
    if (i === tabIndex) btn.classList.add('border-b-2', 'border-yellow-400', 'text-yellow-400');
    else btn.classList.remove('border-b-2', 'border-yellow-400', 'text-yellow-400');
  });
  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  const el = document.getElementById(`tab-content-${tabIndex}`);
  if (el) el.classList.remove('hidden');
}

// ─── Dashboard ──────────────────────────────────────────────────────────────

async function loadDashboard() {
  try {
    const [status, devices, blacklistResp] = await Promise.all([
      api.getStatus(),
      api.getDevices(),
      api.getBlacklistStatus().catch(() => null),
    ]);
    renderStatus(status, devices);
    renderFleet(devices);
    const records = blacklistResp?.data?.blocked_records || [];
    renderBlockedIpList(records);
    syncBlockedEventsToLiveLog(records, false);

    // Start real-time polling for blocked IPs (runs once)
    if (!blockedIpsRefreshStarted) {
      blockedIpsRefreshStarted = true;
      startBlockedIpsRefresh();
    }
  } catch (err) { console.error('Dashboard load error:', err); }
}

function formatBlockTime(isoTimestamp) {
  if (!isoTimestamp) return '--';
  const dt = new Date(isoTimestamp);
  if (Number.isNaN(dt.getTime())) return '--';
  return dt.toLocaleString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    month: 'short',
    day: '2-digit',
  });
}

function renderBlockedIpList(records) {
  const listEl = document.getElementById('blocked-ip-list');
  const countEl = document.getElementById('blocked-ip-count');
  if (!listEl || !countEl) return;

  const safeRecords = Array.isArray(records) ? records : [];
  countEl.textContent = String(safeRecords.filter((r) => r.status === 'blocked').length);

  listEl.innerHTML = '';
  if (!safeRecords.length) {
    listEl.innerHTML = '<div class="text-zinc-500">No blocked suspicious IP yet.</div>';
    return;
  }

  safeRecords.slice(0, 6).forEach((record) => {
    const row = document.createElement('div');
    const statusClass = record.status === 'blocked' ? 'text-red-300' : 'text-amber-300';
    row.className = 'rounded-xl border border-zinc-800 bg-zinc-900/70 p-2.5';
    row.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <span class="font-mono ${statusClass}">${record.ip_address || 'unknown'}</span>
        <span class="text-[10px] uppercase tracking-wide ${statusClass}">${record.status || 'unknown'}</span>
      </div>
      <div class="text-zinc-500 mt-1">${formatBlockTime(record.blocked_at)}</div>
      <div class="text-zinc-400 mt-1">${record.reason || 'Threat intel match'}</div>
    `;
    listEl.append(row);
  });
}

function syncBlockedEventsToLiveLog(records, notify = true, force = false) {
  const safeRecords = Array.isArray(records) ? records : [];
  const ordered = [...safeRecords].reverse();

  ordered.forEach((record) => {
    const recordId = String(record.record_id || `${record.ip_address || 'ip'}-${record.blocked_at || 'time'}`);
    if (seenBlockedRecordIds.has(recordId)) return;

    seenBlockedRecordIds.add(recordId);
    const isBlocked = record.status === 'blocked';
    appendLiveLogEntry({
      type: isBlocked ? 'warning' : 'info',
      timestamp: record.blocked_at,
      eventKey: `blocked:${recordId}`,
      text: `${isBlocked ? 'Blocked suspicious IP' : 'Block attempt failed'} ${record.ip_address || 'unknown'} at ${formatBlockTime(record.blocked_at)}.${record.reason ? ` Reason: ${record.reason}.` : ''}`,
    }, { force });

    if (notify && isBlocked) {
      notifyOnce(`blocked-toast:${recordId}`, `CyberMind blocked risky activity from ${record.ip_address || 'an unknown source'}`);
    }
  });
}

function renderStatus(status, devices) {
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('safety-score', `${status.safetyScore}%`);
  set('ai-confidence', `${status.aiConfidence}%`);
  set('threat-count', status.threatsActive);
  set('last-threat-time', status.lastThreatDetected);
  set('fleet-count', devices.length);
  set('fleet-badge', `${devices.length} DEVICES`);
  set('devices-online-count', devices.filter(d => d.status === 'online').length);
  set('devices-total-count', devices.length);
  set('wifi-ip-display', status.mac_ip || '--');

  const bar = document.getElementById('ai-confidence-bar');
  if (bar) bar.style.width = `${status.aiConfidence}%`;
}

function renderFleet(devices) {
  const container = document.getElementById('fleet-grid');
  if (!container) return;
  container.innerHTML = '';

  const typeIcons = { laptop: 'fa-laptop', server: 'fa-server', mobile: 'fa-mobile-screen', iot: 'fa-microchip' };

  devices.forEach(device => {
    const source = device.source || 'node';
    const sc = device.status === 'online' ? 'emerald' : 'zinc';
    const icon = typeIcons[device.type] || 'fa-laptop';
    const div = document.createElement('div');
    div.className = `bg-zinc-900 border border-${sc}-400/30 rounded-3xl px-6 py-6 card-hover cursor-pointer relative group`;
    div.innerHTML = `
      <div class="absolute top-3 right-3 flex gap-2 btn-delete">
        <button class="edit-device w-7 h-7 bg-zinc-800 hover:bg-amber-400/20 text-zinc-400 hover:text-amber-400 rounded-lg flex items-center justify-center text-xs transition-colors" data-device-id="${device.id}" data-device-source="${source}">
          <i class="fa-solid fa-pen"></i>
        </button>
        <button class="delete-device w-7 h-7 bg-zinc-800 hover:bg-red-400/20 text-zinc-400 hover:text-red-400 rounded-lg flex items-center justify-center text-xs transition-colors" data-device-id="${device.id}" data-device-source="${source}" data-device-name="${device.name}">
          <i class="fa-solid fa-trash"></i>
        </button>
      </div>
      <div class="flex justify-between items-start">
        <div>
          <div class="flex items-center gap-x-2">
            <i class="fa-solid ${icon} text-${sc}-400"></i>
            <span class="font-medium text-white">${device.name}</span>
          </div>
          <div class="text-[10px] text-zinc-500 mt-1">${device.ip || ''} • ${device.type}</div>
          <div class="text-xs mt-5 text-zinc-400">SAFETY</div>
          <div class="flex items-baseline gap-x-1">
            <span class="text-5xl font-semibold text-white">${device.safety}</span>
            <span class="text-xs text-zinc-400">/100</span>
          </div>
        </div>
        <div class="text-right mt-8">
          <span class="toggle-device inline-block text-[10px] px-4 py-1 rounded-3xl bg-${sc}-400/10 text-${sc}-300 cursor-pointer" data-device-id="${device.id}" data-device-source="${source}" data-device-status="${device.status}">
            ${device.status.toUpperCase()}
          </span>
          <div class="mt-6 text-xs text-zinc-400">LAST THREAT</div>
          <div class="text-xs text-white">${device.lastThreat}</div>
        </div>
      </div>
    `;
    container.append(div);
  });
}

// ─── Device CRUD ────────────────────────────────────────────────────────────

function showAddDeviceModal() {
  document.getElementById('new-device-name').value = '';
  document.getElementById('new-device-type').value = 'laptop';
  document.getElementById('new-device-ip').value = '';
  document.getElementById('add-device-modal').classList.remove('hidden');
}

function closeAddDeviceModal() {
  document.getElementById('add-device-modal').classList.add('hidden');
}

async function submitAddDevice() {
  const name = document.getElementById('new-device-name').value.trim();
  const type = document.getElementById('new-device-type').value;
  const ip = document.getElementById('new-device-ip').value.trim();

  if (!name) { showToast('Please enter a device name'); return; }

  try {
    const device = await api.addDevice({ name, type, ip: ip || undefined });
    showToast(`Device "${device.name}" added successfully`);
    closeAddDeviceModal();
    loadDashboard();
  } catch (err) { showToast('Failed to add device'); }
}

async function showEditDeviceModal(id) {
  try {
    let device;
    let source = 'node';

    if (typeof id === 'object' && id !== null) {
      source = id.source || 'node';
      const deviceId = id.id;
      if (source === 'flask') {
        const response = await api.opsGetDevice(deviceId);
        device = {
          id: response?.data?.id,
          name: response?.data?.name,
          type: response?.data?.device_type || 'laptop',
          ip: response?.data?.ip_address || '',
        };
      } else {
        device = await api.getDevice(deviceId);
      }
    } else {
      device = await api.getDevice(id);
    }

    editingDevice = { id: device.id, source };
    document.getElementById('edit-device-name').value = device.name || '';
    document.getElementById('edit-device-type').value = device.type || 'laptop';
    document.getElementById('edit-device-ip').value = device.ip || '';
    document.getElementById('edit-device-modal').classList.remove('hidden');
  } catch (err) { showToast(`Failed to load device: ${err.message}`); }
}

function closeEditDeviceModal() {
  document.getElementById('edit-device-modal').classList.add('hidden');
  editingDevice = null;
}

async function submitEditDevice() {
  if (!editingDevice) return;
  const name = document.getElementById('edit-device-name').value.trim();
  const type = document.getElementById('edit-device-type').value;
  const ip = document.getElementById('edit-device-ip').value.trim();

  if (!name) { showToast('Device name cannot be empty'); return; }

  try {
    if (editingDevice.source === 'flask') {
      await api.opsUpdateDevice(editingDevice.id, {
        name,
        device_type: type,
        ip_address: ip,
      });
    } else {
      await api.updateDevice(editingDevice.id, { name, type, ip });
    }
    showToast('Device updated');
    closeEditDeviceModal();
    loadDashboard();
  } catch (err) { showToast(`Failed to update device: ${err.message}`); }
}

function showDeleteConfirm(id, name, source = 'node') {
  deletingDevice = { id, source };
  document.getElementById('delete-confirm-text').textContent = `Are you sure you want to remove "${name}" from your fleet?`;
  document.getElementById('delete-confirm-modal').classList.remove('hidden');
}

function closeDeleteModal() {
  document.getElementById('delete-confirm-modal').classList.add('hidden');
  deletingDevice = null;
}

async function confirmDeleteDevice() {
  if (!deletingDevice) return;
  try {
    if (deletingDevice.source === 'flask') {
      await api.opsDeleteDevice(deletingDevice.id);
    } else {
      await api.deleteDevice(deletingDevice.id);
    }
    showToast('Device removed from fleet');
    closeDeleteModal();
    loadDashboard();
  } catch (err) { showToast(`Failed to delete device: ${err.message}`); }
}

async function handleToggleDevice(id, source = 'node', currentStatus = 'offline') {
  try {
    if (source === 'flask') {
      const nextStatus = currentStatus === 'online' ? 'offline' : 'online';
      await api.opsUpdateDevice(id, { status: nextStatus });
      showToast(`Device is now ${nextStatus}`);
    } else {
      const device = await api.toggleDevice(id);
      showToast(`${device.name} is now ${device.status}`);
    }
    loadDashboard();
  } catch (err) { showToast(`Failed to update device: ${err.message}`); }
}

// ─── Logs ───────────────────────────────────────────────────────────────────

async function loadLogs() {
  try {
    const logs = await api.getLogs();
    renderLogTable(logs);
  } catch (err) { console.error('Logs load error:', err); }
}

function renderLogTable(logs) {
  const tbody = document.getElementById('log-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  logs.forEach(log => {
    const sevClass = `severity-${log.severity || 'low'}`;
    const row = document.createElement('tr');
    row.className = 'hover:bg-yellow-300/5 transition-colors';
    row.innerHTML = `
      <td class="py-5 px-8 font-mono text-xs text-zinc-400">${log.time}</td>
      <td class="py-5 px-8">${log.device}</td>
      <td class="py-5 px-8 text-amber-300">${log.event}</td>
      <td class="py-5 px-8 text-xs text-white">${log.summary}</td>
      <td class="py-5 px-8"><span class="text-[10px] px-3 py-1 rounded-3xl ${sevClass}">${(log.severity || 'low').toUpperCase()}</span></td>
      <td class="py-5 px-8 text-right"><span class="text-xs px-5 py-2 bg-zinc-800 text-emerald-300 rounded-3xl">${log.action}</span></td>
    `;
    tbody.append(row);
  });
}

// ─── Honeypot ───────────────────────────────────────────────────────────────

async function loadHoneypot() {
  try {
    const data = await api.getHoneypot();
    renderHoneypotTimeline(data.events);
    renderDecoyList(data.decoys);
    const countEl = document.getElementById('honeypot-count');
    if (countEl) countEl.textContent = data.count;
  } catch (err) { console.error('Honeypot load error:', err); }
}

function renderHoneypotTimeline(events) {
  const container = document.getElementById('honeypot-timeline');
  if (!container) return;
  container.innerHTML = '';
  events.forEach((ev, i) => {
    const div = document.createElement('div');
    div.className = 'flex gap-4';
    div.innerHTML = `
      <div class="w-5 h-5 bg-lime-400 text-zinc-950 text-[10px] flex items-center justify-center rounded-xl font-bold">${i + 1}</div>
      <div class="flex-1">
        <div class="flex justify-between text-xs"><div class="text-white">${ev.file}</div><div class="font-mono text-zinc-500">${ev.time}</div></div>
        <div class="text-xs text-lime-300">${ev.detail}</div>
      </div>
    `;
    container.append(div);
  });
}

function renderDecoyList(decoys) {
  const container = document.getElementById('decoy-list');
  if (!container) return;
  container.innerHTML = '';
  decoys.forEach(d => {
    const li = document.createElement('li');
    li.className = 'flex justify-between items-center';
    li.innerHTML = `
      <div class="flex items-center gap-x-3">
        <i class="fa-solid fa-file text-amber-200"></i>
        <div><div class="text-sm">${d.name}</div><div class="text-xs text-zinc-500">modified ${d.modified}</div></div>
      </div>
      <div class="text-emerald-400 text-xs">${d.status}</div>
    `;
    container.append(li);
  });
}

async function handleDeployDecoy() {
  try {
    const decoy = await api.deployDecoy();
    showToast(`Decoy "${decoy.name}" deployed`);
    loadHoneypot();
  } catch (err) { showToast('Failed to deploy decoy'); }
}

async function handleTriggerHoneypot() {
  try {
    const result = await api.triggerHoneypot();
    showToast('New decoy deployed. Monitoring...');
    const countEl = document.getElementById('honeypot-count');
    if (countEl) {
      countEl.style.transition = 'transform 0.4s ease';
      countEl.style.transform = 'scale(1.6)';
      countEl.textContent = result.count;
      setTimeout(() => { countEl.style.transform = 'scale(1)'; }, 420);
    }
  } catch (err) { showToast('Failed to trigger honeypot'); }
}

// ─── Threats ────────────────────────────────────────────────────────────────

async function loadThreats() {
  try {
    const threats = await api.getThreats();
    renderThreatsList(threats);
    document.getElementById('threats-list').classList.remove('hidden');
    document.getElementById('threat-detail').classList.add('hidden');
  } catch (err) { console.error('Threats load error:', err); }
}

function renderThreatsList(threats) {
  const container = document.getElementById('threats-list');
  if (!container) return;
  container.innerHTML = '';

  if (threats.length === 0) {
    container.innerHTML = '<div class="text-center py-16 text-zinc-500"><i class="fa-solid fa-shield-check text-5xl mb-4 text-emerald-400"></i><div class="text-lg">No active threats</div></div>';
    return;
  }

  threats.forEach(threat => {
    const sevColors = { critical: 'red', high: 'orange', medium: 'yellow', low: 'emerald' };
    const color = sevColors[threat.severity] || 'zinc';
    const div = document.createElement('div');
    div.className = `bg-zinc-900 border border-${color}-400/30 rounded-3xl p-6 card-hover cursor-pointer`;
    div.setAttribute('data-action', 'view-threat');
    div.setAttribute('data-threat-id', threat.id);
    div.innerHTML = `
      <div class="flex justify-between items-start">
        <div class="flex items-start gap-x-4">
          <div class="w-10 h-10 bg-${color}-400/10 flex items-center justify-center rounded-xl mt-1">
            <i class="fa-solid fa-triangle-exclamation text-${color}-400"></i>
          </div>
          <div>
            <div class="font-medium text-white text-lg">${threat.title}</div>
            <div class="text-xs text-zinc-400 mt-1">${threat.description.slice(0, 100)}...</div>
            <div class="flex items-center gap-x-4 mt-3">
              <span class="text-[10px] px-3 py-1 rounded-3xl severity-${threat.severity}">${threat.severity.toUpperCase()}</span>
              <span class="text-xs text-zinc-500"><i class="fa-solid fa-crosshairs mr-1"></i>${threat.targetDevice}</span>
              <span class="text-xs text-zinc-500"><i class="fa-solid fa-globe mr-1"></i>${threat.sourceCountry}</span>
            </div>
          </div>
        </div>
        <div class="text-zinc-400"><i class="fa-solid fa-chevron-right"></i></div>
      </div>
    `;
    container.append(div);
  });
}

async function viewThreatDetail(id) {
  try {
    const threat = await api.getThreat(id);
    const sevColors = { critical: 'red', high: 'orange', medium: 'yellow', low: 'emerald' };
    const color = sevColors[threat.severity] || 'zinc';

    document.getElementById('threats-list').classList.add('hidden');
    document.getElementById('threat-detail').classList.remove('hidden');

    const content = document.getElementById('threat-detail-content');
    content.innerHTML = `
      <div class="flex items-start gap-x-4 mb-8">
        <div class="w-14 h-14 bg-${color}-400/10 flex items-center justify-center rounded-2xl">
          <i class="fa-solid fa-triangle-exclamation text-${color}-400 text-2xl"></i>
        </div>
        <div>
          <h2 class="text-2xl font-semibold text-white">${threat.title}</h2>
          <div class="flex items-center gap-x-4 mt-2">
            <span class="text-xs px-3 py-1 rounded-3xl severity-${threat.severity}">${threat.severity.toUpperCase()}</span>
            <span class="text-xs text-zinc-400">${threat.detectedAt}</span>
          </div>
        </div>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div class="bg-zinc-800 rounded-2xl p-4 text-center">
          <div class="text-xs text-zinc-400 mb-1">SOURCE IP</div>
          <div class="font-mono text-sm text-white">${threat.sourceIp}</div>
        </div>
        <div class="bg-zinc-800 rounded-2xl p-4 text-center">
          <div class="text-xs text-zinc-400 mb-1">COUNTRY</div>
          <div class="text-sm text-white">${threat.sourceCountry}</div>
        </div>
        <div class="bg-zinc-800 rounded-2xl p-4 text-center">
          <div class="text-xs text-zinc-400 mb-1">TARGET</div>
          <div class="text-sm text-white">${threat.targetDevice}</div>
        </div>
        <div class="bg-zinc-800 rounded-2xl p-4 text-center">
          <div class="text-xs text-zinc-400 mb-1">ATTEMPTS</div>
          <div class="text-sm text-white">${threat.attempts}</div>
        </div>
      </div>

      <div class="mb-8">
        <div class="text-sm font-medium text-zinc-300 mb-3">Description</div>
        <p class="text-sm text-zinc-400">${threat.description}</p>
      </div>

      <div class="mb-8">
        <div class="text-sm font-medium text-zinc-300 mb-4">Timeline</div>
        <div class="space-y-4">
          ${threat.timeline.map((t, i) => `
            <div class="flex gap-4 items-start">
              <div class="w-2 h-2 bg-${color}-400 rounded-full mt-2 flex-shrink-0"></div>
              <div>
                <span class="font-mono text-xs text-zinc-500">${t.time}</span>
                <span class="text-sm text-white ml-3">${t.event}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      <div>
        <div class="text-sm font-medium text-zinc-300 mb-4">Recommendations</div>
        <div class="space-y-3">
          ${threat.recommendations.map(r => `
            <div class="flex items-start gap-x-3 bg-zinc-800 p-4 rounded-2xl">
              <i class="fa-solid fa-lightbulb text-yellow-400 mt-0.5"></i>
              <span class="text-sm text-zinc-300">${r}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  } catch (err) { showToast('Failed to load threat details'); }
}

// ─── Phishing Check ─────────────────────────────────────────────────────────

async function handleCheckPhishing() {
  const input = document.getElementById('phish-input');
  const resultContainer = document.getElementById('phish-result');
  if (!input || !resultContainer) return;

  const url = input.value.trim();
  if (!url) { showToast('Please enter a URL'); return; }

  try {
    const result = await api.checkPhishing(url);
    const bgColor = result.dangerous ? 'bg-red-900/30' : 'bg-emerald-900/30';
    const textColor = result.dangerous ? 'text-red-400' : 'text-emerald-400';
    const icon = result.dangerous ? 'fa-circle-xmark' : 'fa-circle-check';
    const title = result.dangerous ? 'This link is DANGEROUS' : 'This link appears SAFE';

    resultContainer.innerHTML = `
      <div class="flex items-center gap-x-4 ${bgColor} ${textColor} p-5 rounded-3xl">
        <i class="fa-solid ${icon} text-4xl"></i>
        <div>
          <div class="font-semibold">${title}</div>
          <div class="text-xs mt-1">${result.reason}</div>
          <div class="text-[10px] mt-2 opacity-60">Confidence: ${result.confidence}%</div>
        </div>
      </div>
    `;
    resultContainer.classList.remove('hidden');
    showToast(result.dangerous ? 'Phishing link detected!' : 'Link appears safe');
  } catch (err) { showToast('Failed to check link'); }
}

// ─── Log Translation ────────────────────────────────────────────────────────

async function handleTranslateLog() {
  const el = document.getElementById('translated-log');
  if (!el) return;
  try {
    const result = await api.translateLog('EventCode=4625 AccountName=Administrator');
    el.innerHTML = `<span class="text-emerald-300">Plain English:</span><br><span class="text-white">${result.translation}</span>`;
    el.classList.remove('hidden');
    el.style.opacity = 0;
    setTimeout(() => { el.style.transition = 'opacity 1s'; }, 10);
    setTimeout(() => { el.style.opacity = 1; }, 120);
  } catch (err) { showToast('Translation failed'); }
}

// ─── Remediation ────────────────────────────────────────────────────────────

async function handleRunPlaybook(n) {
  try { const r = await api.runRemediation(n); showToast(r.message); } catch (err) { showToast('Playbook failed'); }
}

// ─── Kill Switch ────────────────────────────────────────────────────────────

function showKillModal() {
  const m = document.getElementById('kill-modal');
  m.classList.remove('hidden'); m.classList.add('flex');
}

async function handleTriggerKillSwitch() {
  try {
    const r = await api.activateKillSwitch(2);
    document.getElementById('kill-modal').classList.add('hidden');
    showToast(r.message);
    loadDashboard();
  } catch (err) { showToast('Kill switch failed'); }
}

// ─── Network Scan ───────────────────────────────────────────────────────────

async function handleRunScan() {
  const overlay = document.getElementById('scan-overlay');
  const content = document.getElementById('scan-content');

  overlay.classList.remove('hidden');
  content.innerHTML = `
    <div class="text-center py-12">
      <i class="fa-solid fa-spinner fa-spin text-4xl text-sky-400 mb-4"></i>
      <div class="text-sm text-zinc-400 scan-pulse">Scanning network...</div>
      <div class="scan-progress mt-6 mx-auto max-w-xs"><div class="scan-progress-bar"></div></div>
    </div>
  `;

  try {
    await new Promise(r => setTimeout(r, 3000));
    const result = await api.runScan();

    content.innerHTML = `
      <div class="mb-6">
        <div class="flex items-center gap-x-4">
          <div class="text-emerald-400"><i class="fa-solid fa-circle-check text-2xl"></i></div>
          <div>
            <div class="font-medium text-white">Scan Complete</div>
            <div class="text-xs text-zinc-400">${result.results.length} devices scanned • ${result.totalVulnerabilities} vulnerabilities found</div>
          </div>
        </div>
      </div>
      <div class="space-y-4">
        ${result.results.map(r => `
          <div class="bg-zinc-800 rounded-2xl p-5">
            <div class="flex justify-between items-start mb-3">
              <div>
                <div class="font-medium text-white">${r.deviceName}</div>
                <div class="text-xs text-zinc-500">${r.ip} • ${r.scanDuration}</div>
              </div>
              <span class="text-[10px] px-3 py-1 rounded-3xl ${r.status === 'online' ? 'bg-emerald-400/10 text-emerald-400' : 'bg-zinc-700 text-zinc-400'}">${r.status.toUpperCase()}</span>
            </div>
            ${r.openPorts.length > 0 ? `<div class="text-xs text-zinc-400 mb-2">Open ports: ${r.openPorts.map(p => `<span class="text-sky-300">${p}</span>`).join(', ')}</div>` : ''}
            ${r.vulnerabilities.length > 0 ? `
              <div class="space-y-2 mt-3">
                ${r.vulnerabilities.map(v => `
                  <div class="flex items-center gap-x-2 text-xs">
                    <span class="px-2 py-0.5 rounded severity-${v.severity}">${v.severity.toUpperCase()}</span>
                    <span class="text-zinc-300">${v.description}</span>
                  </div>
                `).join('')}
              </div>
            ` : '<div class="text-xs text-emerald-400 mt-2"><i class="fa-solid fa-check mr-1"></i>No vulnerabilities found</div>'}
          </div>
        `).join('')}
      </div>
    `;
    showToast(`Scan complete: ${result.totalVulnerabilities} vulnerabilities found`);
  } catch (err) {
    content.innerHTML = '<div class="text-center py-12 text-red-400"><i class="fa-solid fa-circle-xmark text-4xl mb-4"></i><div>Scan failed</div></div>';
  }
}

// ─── Settings ───────────────────────────────────────────────────────────────

async function loadSettings() {
  try {
    const [s, userProfile] = await Promise.all([api.getSettings(), loadUserProfile()]);
    document.getElementById('settings-company').value = s.companyName || '';
    document.getElementById('settings-scan-interval').value = s.autoScanInterval || 30;
    document.getElementById('settings-retention').value = s.retentionDays || 90;
    document.getElementById('settings-alert-email').value = s.alertEmail || '';

    setToggle('toggle-autoblock', s.autoBlockThreats);
    setToggle('toggle-notifications', s.notificationsEnabled);
    setToggle('toggle-email-alerts', s.emailAlertsEnabled);
    setToggle('toggle-alert-high', s.alertOnHigh);
    setToggle('toggle-alert-medium', s.alertOnMedium);
    setToggle('toggle-alert-low', s.alertOnLow);

    // Load sessions
    await loadUserSessions();
  } catch (err) { console.error('Settings load error:', err); }
}

function setToggle(id, active) {
  const el = document.getElementById(id);
  if (!el) return;
  if (active) el.classList.add('active');
  else el.classList.remove('active');
}

async function loadUserSessions() {
  try {
    const sessions = await api.getSessions();
    const container = document.getElementById('sessions-list');
    const logoutOthersBtn = document.getElementById('logout-other-sessions-btn');

    container.innerHTML = '';

    if (sessions.length === 0) {
      container.innerHTML = '<div class="text-center py-8 text-zinc-400">No active sessions</div>';
      logoutOthersBtn.classList.add('hidden');
      return;
    }

    const otherSessions = sessions.filter(s => !s.isCurrent);
    if (otherSessions.length > 0) {
      logoutOthersBtn.classList.remove('hidden');
    } else {
      logoutOthersBtn.classList.add('hidden');
    }

    sessions.forEach(session => {
      const loginDate = new Date(session.loginTime);
      const lastActivityDate = new Date(session.lastActivity);
      const distanceFromNow = (date) => {
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes} min ago`;
        if (hours < 24) return `${hours} hrs ago`;
        return `${days} days ago`;
      };

      const item = document.createElement('div');
      item.className = `bg-zinc-800 rounded-lg p-4 border-l-4 ${session.isCurrent ? 'border-yellow-400' : 'border-zinc-700'}`;

      item.innerHTML = `
        <div class="flex justify-between items-start">
          <div class="flex-1">
            <div class="font-medium text-zinc-300">
              <i class="fa-solid ${session.browser === 'Chrome' ? 'fa-chrome' : session.browser === 'Firefox' ? 'fa-firefox' : 'fa-globe'} mr-2"></i>
              ${session.browser} on ${session.os}
              ${session.isCurrent ? '<span class="ml-2 px-2 py-1 text-xs bg-yellow-400/20 text-yellow-400 rounded">CURRENT</span>' : ''}
            </div>
            <div class="text-xs text-zinc-500 mt-2">
              <i class="fa-solid fa-map-marker mr-1"></i>IP: ${session.ip}
            </div>
            <div class="text-xs text-zinc-500 mt-1">
              <i class="fa-solid fa-clock mr-1"></i>Last active: ${distanceFromNow(lastActivityDate)}
            </div>
            <div class="text-xs text-zinc-500 mt-1">
              Login: ${loginDate.toLocaleDateString()} ${loginDate.toLocaleTimeString()}
            </div>
          </div>
          ${!session.isCurrent ? `
            <button data-session-id="${session.sessionId}" class="logout-session ml-4 px-3 py-1 text-xs bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded transition">
              Logout
            </button>
          ` : ''}
        </div>
      `;

      container.appendChild(item);
    });
  } catch (err) {
    document.getElementById('sessions-list').innerHTML = `<div class="text-red-400 text-sm"><i class="fa-solid fa-exclamation mr-2"></i>Failed to load sessions</div>`;
  }
}

function handleToggleSetting(el) {
  el.classList.toggle('active');
}

async function saveSettings() {
  const data = {
    companyName: document.getElementById('settings-company').value.trim(),
    autoBlockThreats: document.getElementById('toggle-autoblock').classList.contains('active'),
    notificationsEnabled: document.getElementById('toggle-notifications').classList.contains('active'),
    emailAlertsEnabled: document.getElementById('toggle-email-alerts').classList.contains('active'),
    alertEmail: document.getElementById('settings-alert-email').value.trim(),
    alertOnHigh: document.getElementById('toggle-alert-high').classList.contains('active'),
    alertOnMedium: document.getElementById('toggle-alert-medium').classList.contains('active'),
    alertOnLow: document.getElementById('toggle-alert-low').classList.contains('active'),
    autoScanInterval: parseInt(document.getElementById('settings-scan-interval').value) || 30,
    retentionDays: parseInt(document.getElementById('settings-retention').value) || 90,
  };

  try {
    await api.updateSettings(data);
    showToast('Settings saved successfully');
  } catch (err) { showToast('Failed to save settings'); }
}

// ─── Live Feed ──────────────────────────────────────────────────────────────

async function refreshLogs() {
  const logContainer = document.getElementById('live-log');
  if (!logContainer) return;

  try {
    const [msg, blacklistResp] = await Promise.all([
      api.getLiveFeed(),
      api.getBlacklistStatus().catch(() => null),
    ]);

    if (msg?.text) {
      appendLiveLogEntry({ ...msg, eventKey: `refresh-live:${msg.text}` }, { force: true });
    }

    const records = blacklistResp?.data?.blocked_records || [];
    renderBlockedIpList(records);
    syncBlockedEventsToLiveLog(records, false, true);

    getNextMockAttackEvents(5).forEach((entry) => appendLiveLogEntry(entry, { force: true }));
    showToast('Newest simulated attacks loaded');
  } catch (err) {
    showToast('Failed to refresh logs');
  }
}

function appendLiveLogEntry(msg, options = {}) {
  const liveLog = document.getElementById('live-log');
  if (!liveLog || !msg?.text) return;

  const safeText = toOwnerFriendlyText(msg.text, msg.type);
  const eventKey = msg.eventKey || `${msg.type || 'info'}:${safeText}`;
  if (!options.force && seenLiveEventKeys.has(eventKey)) return;
  seenLiveEventKeys.add(eventKey);

  const colorMap = {
    info: 'text-sky-200',
    warning: 'text-amber-300',
    success: 'text-emerald-300',
    error: 'text-red-300',
  };

  const entry = document.createElement('div');
  entry.className = `log-line mt-4 ${colorMap[msg.type] || 'text-white'}`;
  const prefix = msg.timestamp ? `[${formatBlockTime(msg.timestamp)}] ` : '';
  entry.innerHTML = `→ ${prefix}${safeText}`;
  liveLog.append(entry);

  while (liveLog.children.length > 35) {
    liveLog.removeChild(liveLog.children[0]);
  }

  liveLog.scrollTop = liveLog.scrollHeight;
}

function getNextMockAttackEvents(count = 1) {
  const now = Date.now();
  const events = [];

  for (let i = 0; i < count; i += 1) {
    const scenario = MOCK_ATTACK_SCENARIOS[mockAttackCursor % MOCK_ATTACK_SCENARIOS.length];
    mockAttackCursor += 1;
    events.push({
      type: scenario.type,
      text: scenario.type === 'warning'
        ? `We blocked unusual activity from ${scenario.ip}. Your systems are safe.`
        : `We checked unusual activity from ${scenario.ip} and kept your systems safe.`,
      timestamp: new Date(now - (count - i - 1) * 25000).toISOString(),
      eventKey: `mock:${scenario.attack}:${scenario.ip}:${mockAttackCursor}`,
    });
  }

  return events;
}

function seedMockAttackHistory() {
  const liveLog = document.getElementById('live-log');
  if (!liveLog) return;

  liveLog.innerHTML = '';
  getNextMockAttackEvents(30).forEach((entry) => appendLiveLogEntry(entry, { force: true }));
}

function generateFakeLogActivity() {
  setInterval(async () => {
    if (currentScreen !== 'dashboard') return;
    try {
      const [msg, blacklistResp] = await Promise.all([
        api.getLiveFeed(),
        api.getBlacklistStatus().catch(() => null),
      ]);
      if (msg?.text && msg.text !== lastLiveFeedText) {
        lastLiveFeedText = msg.text;
        appendLiveLogEntry({ ...msg, eventKey: `live:${msg.text}` });
        if (msg.type === 'warning') {
          notifyOnce(`warn:${msg.text}`, `Alert: ${msg.text}`);
        }
      }

      const records = blacklistResp?.data?.blocked_records || [];
      renderBlockedIpList(records);
      syncBlockedEventsToLiveLog(records, true);

      getNextMockAttackEvents(1).forEach((entry) => appendLiveLogEntry(entry));
    } catch (_) { }
  }, 6500);
}

// ─── Aggressive Blocked IPs Refresh (for real-time demo) ────────────────────
function startBlockedIpsRefresh() {
  setInterval(async () => {
    if (currentScreen !== 'dashboard') return;
    try {
      const blacklistResp = await api.getBlacklistStatus().catch(() => null);
      if (!blacklistResp) return;

      const records = blacklistResp?.data?.blocked_records || [];
      if (records.length > 0) {
        renderBlockedIpList(records);
        syncBlockedEventsToLiveLog(records, true);
      }
    } catch (_) { }
  }, 2000); // Poll every 2 seconds for real-time updates
}

// ─── Voice Alert ────────────────────────────────────────────────────────────

function speakLastAlert() {
  if ('speechSynthesis' in window) {
    const u = new SpeechSynthesisUtterance('Warning. Brute force password attack detected from external IP.');
    u.pitch = 0.9; u.rate = 1.05;
    speechSynthesis.speak(u);
  } else showToast('AI voice alert: Brute force attack detected');
}

// ─── Keyboard Shortcuts ─────────────────────────────────────────────────────

function handleKeyboard(e) {
  if (e.metaKey && e.key === 'k') { e.preventDefault(); showToast('Command palette (demo)'); }
  if (e.key === 'Escape') {
    document.getElementById('kill-modal')?.classList.add('hidden');
    document.getElementById('add-device-modal')?.classList.add('hidden');
    document.getElementById('edit-device-modal')?.classList.add('hidden');
    document.getElementById('delete-confirm-modal')?.classList.add('hidden');
    document.getElementById('scan-overlay')?.classList.add('hidden');
  }
}

// ─── Event Delegation ───────────────────────────────────────────────────────

function wireEvents() {
  // Auth forms
  document.getElementById('login-form')?.addEventListener('submit', handleLogin);
  document.getElementById('signup-form')?.addEventListener('submit', handleSignup);
  document.getElementById('forgot-password-form')?.addEventListener('submit', handleForgotPassword);
  document.getElementById('reset-password-form')?.addEventListener('submit', handleResetPassword);
  document.getElementById('email-verification-form')?.addEventListener('submit', handleEmailVerification);

  // Auth tabs
  document.getElementById('login-tab')?.addEventListener('click', () => switchAuthTab('login'));
  document.getElementById('signup-tab')?.addEventListener('click', () => switchAuthTab('signup'));

  // Forgot password flow
  document.getElementById('forgot-password-btn')?.addEventListener('click', () => switchAuthFlow('forgot'));
  document.getElementById('back-to-login-btn')?.addEventListener('click', () => switchAuthFlow('login'));
  document.getElementById('back-to-forgot-btn')?.addEventListener('click', () => switchAuthFlow('forgot'));

  // Admin tabs
  document.querySelectorAll('.admin-tab').forEach(btn => {
    btn.addEventListener('click', () => switchAdminTab(btn.dataset.adminTab));
  });

  // Activity filter
  document.getElementById('activity-username-filter')?.addEventListener('input', async (e) => {
    const username = e.target.value.trim();
    try {
      if (username) {
        const activity = await api.getUserLoginActivity(username);
        const container = document.getElementById('admin-activity-list');
        container.innerHTML = '';

        if (activity.length === 0) {
          container.innerHTML = `<div class="text-center py-8 text-zinc-400">No activity found for "${username}"</div>`;
          return;
        }

        activity.forEach(entry => {
          const date = new Date(entry.timestamp);
          const dateStr = date.toLocaleDateString();
          const timeStr = date.toLocaleTimeString();

          const item = document.createElement('div');
          item.className = 'bg-zinc-800 rounded-lg p-4 border-l-4 ' +
            (entry.success ? 'border-emerald-400' : 'border-red-400');

          item.innerHTML = `
            <div class="flex justify-between items-start">
              <div>
                <div class="font-medium text-zinc-300">${entry.username}</div>
                <div class="text-sm text-zinc-400 mt-1">
                  ${entry.success ? '<i class="fa-solid fa-check text-emerald-400"></i>' : '<i class="fa-solid fa-xmark text-red-400"></i>'}
                  ${entry.success ? 'Successful login' : 'Failed login - ' + (entry.reason || 'Unknown')}
                </div>
                <div class="text-xs text-zinc-500 mt-2">
                  <i class="fa-solid fa-globe mr-1"></i>${entry.ip}
                </div>
              </div>
              <div class="text-right text-xs text-zinc-500">
                <div>${dateStr}</div>
                <div>${timeStr}</div>
              </div>
            </div>
          `;

          container.appendChild(item);
        });
      } else {
        loadAdminActivity();
      }
    } catch (err) {
      showToast('Failed to filter activity: ' + err.message);
    }
  });

  // Auth expired
  window.addEventListener('auth:expired', () => { showLogin(); showToast('Session expired. Please sign in again.'); });

  // Main click delegation
  document.addEventListener('click', (e) => {
    const target = e.target.closest('[data-action]');
    if (!target) return;

    const action = target.dataset.action;
    switch (action) {
      case 'navigate': navigateTo(target.dataset.screen); break;
      case 'navigate-mobile': navigateTo(target.dataset.screen); toggleMobileMenu(); break;
      case 'toggle-mobile-menu': toggleMobileMenu(); break;
      case 'show-add-device-modal': showAddDeviceModal(); break;
      case 'update-profile': handleUpdateProfile(); break;
      case 'change-password': handleChangePassword(); break;
      case 'close-add-device-modal': closeAddDeviceModal(); break;
      case 'submit-add-device': submitAddDevice(); break;
      case 'close-edit-device-modal': closeEditDeviceModal(); break;
      case 'submit-edit-device': submitEditDevice(); break;
      case 'close-delete-modal': closeDeleteModal(); break;
      case 'confirm-delete-device': confirmDeleteDevice(); break;
      case 'refresh-logs': refreshLogs(); break;
      case 'speak-alert': speakLastAlert(); break;
      case 'run-playbook': handleRunPlaybook(parseInt(target.dataset.playbook)); break;
      case 'run-scan': handleRunScan(); break;
      case 'close-scan': document.getElementById('scan-overlay').classList.add('hidden'); break;
      case 'kill-switch': showKillModal(); break;
      case 'kill-switch-confirm': handleTriggerKillSwitch(); break;
      case 'kill-switch-dismiss': document.getElementById('kill-modal').classList.add('hidden'); break;
      case 'switch-tab': switchTab(parseInt(target.dataset.tab)); break;
      case 'trigger-honeypot': handleTriggerHoneypot(); break;
      case 'check-phishing': handleCheckPhishing(); break;
      case 'translate-log': handleTranslateLog(); break;
      case 'deploy-decoy': handleDeployDecoy(); break;
      case 'save-settings': saveSettings(); break;
      case 'toggle-setting': handleToggleSetting(target); break;
      case 'toggle-theme': toggleTheme(); break;
      case 'view-threat': viewThreatDetail(parseInt(target.dataset.threatId)); break;
      case 'close-threat-detail': loadThreats(); break;
      case 'logout': handleLogout(); break;
    }
  });

  // Admin user actions delegated events
  document.addEventListener('click', async (e) => {
    const adminBtn = e.target.closest('[data-admin-action]');
    if (!adminBtn) return;

    const action = adminBtn.dataset.adminAction;
    const userId = parseInt(adminBtn.dataset.userId);

    try {
      if (action === 'delete-user') {
        if (!confirm('Are you sure you want to delete this user? This cannot be undone.')) return;
        await api.deleteUser(userId);
        showToast('User deleted successfully');
        loadAdminUsers();
      } else if (action === 'make-admin') {
        await api.makeUserAdmin(userId);
        showToast('User promoted to admin');
        loadAdminUsers();
      } else if (action === 'remove-admin') {
        await api.removeUserAdmin(userId);
        showToast('User removed from admin role');
        loadAdminUsers();
      } else if (action === 'reset-password') {
        if (!confirm('Send a password reset email to this user?')) return;
        await api.resetUserPassword(userId);
        showToast('Password reset email sent');
        loadAdminUsers();
      }
    } catch (err) {
      showToast('Admin action failed: ' + err.message);
    }
  });

  // Session logout handlers
  document.addEventListener('click', async (e) => {
    if (e.target.closest('.logout-session')) {
      e.stopPropagation();
      const btn = e.target.closest('.logout-session');
      const sessionId = btn.dataset.sessionId;

      try {
        await api.logoutSession(sessionId);
        showToast('Session logged out');
        await loadUserSessions();
      } catch (err) {
        showToast('Failed to logout session: ' + err.message);
      }
      return;
    }

    if (e.target.id === 'logout-other-sessions-btn') {
      if (!confirm('This will logout all other sessions. Continue?')) return;

      try {
        await api.logoutOtherSessions();
        showToast('All other sessions logged out');
        await loadUserSessions();
      } catch (err) {
        showToast('Failed to logout other sessions: ' + err.message);
      }
      return;
    }
  });

  // Fleet grid delegated events
  document.addEventListener('click', (e) => {
    const toggle = e.target.closest('.toggle-device');
    if (toggle) {
      e.stopPropagation();
      handleToggleDevice(toggle.dataset.deviceId, toggle.dataset.deviceSource || 'node', toggle.dataset.deviceStatus || 'offline');
      return;
    }

    const editBtn = e.target.closest('.edit-device');
    if (editBtn) {
      e.stopPropagation();
      showEditDeviceModal({ id: editBtn.dataset.deviceId, source: editBtn.dataset.deviceSource || 'node' });
      return;
    }

    const deleteBtn = e.target.closest('.delete-device');
    if (deleteBtn) {
      e.stopPropagation();
      showDeleteConfirm(deleteBtn.dataset.deviceId, deleteBtn.dataset.deviceName, deleteBtn.dataset.deviceSource || 'node');
      return;
    }
  });

  // Kill modal backdrop
  const killModal = document.getElementById('kill-modal');
  if (killModal) killModal.addEventListener('click', (e) => { if (e.target.id === 'kill-modal') killModal.classList.add('hidden'); });

  // Toast dismiss
  document.getElementById('toast')?.addEventListener('click', function () { this.classList.add('hidden'); });

  // Keyboard
  document.addEventListener('keydown', handleKeyboard);

  // Keyboard navigation inside the live log pane.
  const liveLogPanel = document.getElementById('live-log');
  if (liveLogPanel) {
    liveLogPanel.addEventListener('mouseenter', () => liveLogPanel.focus());
    liveLogPanel.addEventListener('click', () => liveLogPanel.focus());

    liveLogPanel.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        liveLogPanel.scrollTop += 32;
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        liveLogPanel.scrollTop -= 32;
      }
    });

    // Keep mouse-wheel scroll trapped inside this panel.
    liveLogPanel.addEventListener('wheel', (e) => {
      e.preventDefault();
      liveLogPanel.scrollTop += e.deltaY;
    }, { passive: false });
  }
}

// ─── Initialization ─────────────────────────────────────────────────────────

async function initialize() {
  applyTheme(getSavedTheme());
  wireEvents();
  const authed = await checkAuth();

  if (authed) {
    seedMockAttackHistory();
    generateFakeLogActivity();
  }

  console.log('%c✅ CyberMind Sentinel ready.', 'font-family:monospace;color:#facc15;font-size:10px');
}

window.addEventListener('DOMContentLoaded', initialize);
