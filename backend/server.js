const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const { sendVerificationEmail, sendPasswordResetEmail } = require('./email');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

// ─── Database File Path ─────────────────────────────────────────────────────

const USERS_FILE = path.join(__dirname, 'users.json');
const DEVICES_FILE = path.join(__dirname, 'devices.json');
const LOGS_FILE = path.join(__dirname, 'logs.json');

const ROLE_LEVELS = {
  'viewer': 1,
  'analyst': 2,
  'admin': 3,
  'super-admin': 4,
};

// ─── Load Users from File ───────────────────────────────────────────────────

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = fs.readFileSync(USERS_FILE, 'utf8');
      return JSON.parse(data).users;
    }
  } catch (err) {
    console.error('Error loading users:', err.message);
  }
  return [];
}

function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify({ users }, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving users:', err.message);
  }
}

function getNextUserId(users) {
  return users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1;
}

function loadCollection(filePath, fallbackData) {
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (err) {
    console.error(`Error loading ${path.basename(filePath)}:`, err.message);
  }
  return fallbackData;
}

function saveCollection(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`Error saving ${path.basename(filePath)}:`, err.message);
  }
}

function resolveUserRole(user) {
  if (user && typeof user.role === 'string' && ROLE_LEVELS[user.role]) {
    return user.role;
  }

  if (user && user.username === 'admin') {
    return 'super-admin';
  }

  if (user && user.isAdmin) {
    return 'admin';
  }

  return 'viewer';
}

function isRoleAllowed(currentRole, minimumRole) {
  const current = ROLE_LEVELS[currentRole] || ROLE_LEVELS.viewer;
  const minimum = ROLE_LEVELS[minimumRole] || ROLE_LEVELS.viewer;
  return current >= minimum;
}

// ─── In-Memory Data ─────────────────────────────────────────────────────────

// Auth
let USERS = loadUsers();
let usersMigrated = false;
USERS = USERS.map((user) => {
  const role = resolveUserRole(user);
  const isAdmin = role === 'admin' || role === 'super-admin';
  if (user.role !== role || user.isAdmin !== isAdmin) {
    usersMigrated = true;
  }
  return { ...user, role, isAdmin };
});
if (usersMigrated) {
  saveUsers(USERS);
}
const sessions = new Map();

// Failed login attempts tracking (for rate limiting)
const failedLoginAttempts = new Map(); // key: username, value: { count, blockUntil }

// Login activity log
let loginActivityLog = [];

// Email verification tokens
const emailVerificationTokens = new Map(); // key: token, value: { email, expiresAt }

// User sessions tracking - key: userId, value: [{ sessionId, token, deviceInfo, ip, loginTime, lastActivity }]
const userSessions = new Map();

// Devices — start empty; users add real devices via the UI
let devices = loadCollection(DEVICES_FILE, []);
let nextDeviceId = devices.length > 0 ? Math.max(...devices.map(d => d.id)) + 1 : 1;

// Logs — start empty; only real events are added via detect-attack / scan / honeypot
let logs = loadCollection(LOGS_FILE, []);
let nextLogId = logs.length > 0 ? Math.max(...logs.map(l => l.id)) + 1 : 1;

// Ensure baseline persistence files exist.
if (!fs.existsSync(DEVICES_FILE)) saveCollection(DEVICES_FILE, devices);
if (!fs.existsSync(LOGS_FILE)) saveCollection(LOGS_FILE, logs);

// Honeypot — empty; real data comes from Flask /api/honeypot/logs and /api/honeypot/status
let honeypotData = { count: 0, events: [], decoys: [] };
let nextHoneypotEventId = 1;
let nextDecoyId = 1;

// Threats — dynamically populated when detect-attack is called; starts empty
let threats = [];
let nextThreatId = 1;

// Settings
let settings = {
  companyName: 'Acme Bakery',
  autoBlockThreats: true,
  notificationsEnabled: true,
  emailAlertsEnabled: false,
  alertEmail: '',
  alertOnHigh: true,
  alertOnMedium: false,
  alertOnLow: false,
  darkMode: true,
  autoScanInterval: 30,
  retentionDays: 90,
};

// System Status — real values; stats update when detect-attack is called
let systemStatus = {
  status: 'online',
  safetyScore: 100,
  aiConfidence: 90,
  threatsActive: 0,
  lastThreatDetected: 'None',
};

// Phishing patterns
const PHISHING_PATTERNS = [
  'secure-bank-login', 'account-verify', 'paypa1', 'login-update',
  'free-prize', 'claim-bonus', 'urgent-action', 'suspended-account',
  'microsoft-alert', 'apple-id-lock', 'netflix-payment', 'amazon-security',
];

// ─── IP Blocklist (Demo Attack Detection) ───────────────────────────────────

const BLOCKLIST_FILE = path.join(__dirname, 'blocklist.json');

function loadBlocklist() {
  try {
    if (fs.existsSync(BLOCKLIST_FILE)) {
      return JSON.parse(fs.readFileSync(BLOCKLIST_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading blocklist:', err.message);
  }
  return [];
}

function saveBlocklist(list) {
  try {
    fs.writeFileSync(BLOCKLIST_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving blocklist:', err.message);
  }
}

let ipBlocklist = loadBlocklist();
let nextBlockId = ipBlocklist.length > 0 ? Math.max(...ipBlocklist.map(b => b.id)) + 1 : 1;

// Attack type classifier — maps keywords to human-readable threat types
const ATTACK_SIGNATURES = {
  brute_force:    ['brute', 'login', 'ssh', 'password', 'credential', 'auth'],
  port_scan:      ['scan', 'nmap', 'probe', 'port', 'sweep', 'enumerate'],
  sql_injection:  ['sql', 'inject', "' or", 'union select', 'drop table', '--'],
  xss:            ['<script', 'onerror=', 'alert(', 'javascript:', 'onload='],
  ddos:           ['ddos', 'flood', 'dos', 'amplification', 'overload'],
  malware:        ['malware', 'ransomware', 'trojan', 'payload', 'exploit', 'shell'],
  recon:          ['recon', 'whoami', 'ifconfig', 'uname', 'curl', 'wget'],
};

function classifyAttack(payload = '', threatType = '') {
  const text = (payload + ' ' + threatType).toLowerCase();
  for (const [type, keywords] of Object.entries(ATTACK_SIGNATURES)) {
    if (keywords.some(k => text.includes(k))) return type;
  }
  return 'suspicious_activity';
}

function getSeverity(attackType) {
  const map = {
    brute_force: 'high',
    port_scan: 'medium',
    sql_injection: 'critical',
    xss: 'medium',
    ddos: 'critical',
    malware: 'critical',
    recon: 'low',
    suspicious_activity: 'medium',
  };
  return map[attackType] || 'medium';
}

// ─── Helper Functions ───────────────────────────────────────────────────────

// Rate limiting: Check if user is blocked due to failed attempts
function isUserBlocked(username) {
  const attempt = failedLoginAttempts.get(username);
  if (!attempt) return false;
  
  if (Date.now() > attempt.blockUntil) {
    failedLoginAttempts.delete(username);
    return false;
  }
  
  return attempt.count >= 5;
}

// Record failed login attempt
function recordFailedLogin(username) {
  const attempt = failedLoginAttempts.get(username) || { count: 0, blockUntil: Date.now() };
  attempt.count++;
  attempt.blockUntil = Date.now() + 15 * 60 * 1000; // Block for 15 minutes
  failedLoginAttempts.set(username, attempt);
}

// Clear failed attempts on successful login
function clearFailedAttempts(username) {
  failedLoginAttempts.delete(username);
}

// Log login activity
function logLoginActivity(username, success, ip, reason = '') {
  loginActivityLog.unshift({
    id: loginActivityLog.length + 1,
    username,
    success,
    ip: ip || 'unknown',
    timestamp: new Date().toISOString(),
    reason
  });
  // Keep last 1000 entries
  if (loginActivityLog.length > 1000) loginActivityLog.pop();
}

// Generate email verification token
function generateEmailToken(email) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  emailVerificationTokens.set(token, { email, expiresAt });
  return token;
}

// Verify email token
function verifyEmailToken(token) {
  const data = emailVerificationTokens.get(token);
  if (!data) return null;
  if (Date.now() > data.expiresAt) {
    emailVerificationTokens.delete(token);
    return null;
  }
  emailVerificationTokens.delete(token);
  return data.email;
}

// Extract device info from User-Agent
function parseUserAgent(userAgent) {
  const ua = userAgent || 'Unknown';
  
  let browser = 'Unknown';
  let os = 'Unknown';
  
  // Simple parsing - you could use 'ua-parser-js' npm package for more accuracy
  if (ua.includes('Chrome')) browser = 'Chrome';
  else if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Safari')) browser = 'Safari';
  else if (ua.includes('Edge')) browser = 'Edge';
  
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  else if (ua.includes('Android')) os = 'Android';
  
  return { browser, os };
}

// Create session for user
function createUserSession(userId, token, ip, userAgent) {
  const deviceInfo = parseUserAgent(userAgent);
  
  const session = {
    sessionId: crypto.randomBytes(16).toString('hex'),
    token,
    browser: deviceInfo.browser,
    os: deviceInfo.os,
    ip: ip || 'unknown',
    loginTime: new Date().toISOString(),
    lastActivity: new Date().toISOString(),
  };
  
  if (!userSessions.has(userId)) {
    userSessions.set(userId, []);
  }
  
  userSessions.get(userId).push(session);
  return session;
}

// Get user sessions
function getUserSessions(userId) {
  return userSessions.get(userId) || [];
}

// Logout specific session
function logoutSession(userId, sessionId) {
  if (!userSessions.has(userId)) return false;
  const sessions = userSessions.get(userId);
  const index = sessions.findIndex(s => s.sessionId === sessionId);
  if (index >= 0) {
    sessions.splice(index, 1);
    return true;
  }
  return false;
}

// Logout all sessions except current
function logoutOtherSessions(userId, currentSessionId) {
  if (!userSessions.has(userId)) return;
  const sessions = userSessions.get(userId);
  userSessions.set(userId, sessions.filter(s => s.sessionId === currentSessionId));
}

// ─── Auth Middleware ────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const sessionUser = sessions.get(token);
  const dbUser = USERS.find(u => u.id === sessionUser.id);
  const role = resolveUserRole(dbUser || sessionUser);
  sessionUser.role = role;
  sessionUser.isAdmin = role === 'admin' || role === 'super-admin';
  req.user = sessionUser;
  next();
}

function requireRole(minimumRole) {
  return (req, res, next) => {
    authMiddleware(req, res, () => {
      const role = req.user?.role || 'viewer';
      if (!isRoleAllowed(role, minimumRole)) {
        return res.status(403).json({
          error: `Insufficient role. Required: ${minimumRole}, current: ${role}`,
        });
      }
      next();
    });
  };
}

// Admin middleware
function adminMiddleware(req, res, next) {
  return requireRole('admin')(req, res, next);
}

function superAdminMiddleware(req, res, next) {
  return requireRole('super-admin')(req, res, next);
}

// ─── Auth Routes ────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, confirmPassword, name, company } = req.body;

  // Validation
  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  // Check if user already exists
  if (USERS.find(u => u.username === username)) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  if (USERS.find(u => u.email === email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate email verification token
    const emailToken = generateEmailToken(email);

    // Create new user
    const newUser = {
      id: getNextUserId(USERS),
      username,
      email,
      password: hashedPassword,
      name: name || username,
      company: company || 'Acme Bakery',
      createdAt: new Date().toISOString().split('T')[0],
      resetToken: null,
      resetExpires: null,
      emailVerified: false,
      role: 'viewer',
      isAdmin: false,
      lastLogin: null,
      loginCount: 0
    };

    USERS.push(newUser);
    saveUsers(USERS);

    // Send verification email
    try {
      await sendVerificationEmail(email, emailToken);
    } catch (emailErr) {
      console.error('Failed to send verification email:', emailErr.message);
      // Continue even if email fails - user can still verify
    }

    res.status(201).json({
      success: true,
      message: 'Account created! Check your email for verification code.',
      user: { id: newUser.id, username: newUser.username, name: newUser.name, email: newUser.email },
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Email verification
app.post('/api/auth/verify-email', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });

  const email = verifyEmailToken(token);
  if (!email) return res.status(400).json({ error: 'Invalid or expired token' });

  const user = USERS.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.emailVerified = true;
  saveUsers(USERS);

  res.json({ success: true, message: 'Email verified successfully! You can now login.' });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip || 'unknown';
  const allowUnverifiedLogin = process.env.ALLOW_UNVERIFIED_LOGIN === 'true';
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  // Check rate limiting
  if (isUserBlocked(username)) {
    logLoginActivity(username, false, ip, 'Rate limited - too many failed attempts');
    return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
  }

  const user = USERS.find(u => u.username === username);
  if (!user) {
    recordFailedLogin(username);
    logLoginActivity(username, false, ip, 'User not found');
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Check email verified
  if (!user.emailVerified && !allowUnverifiedLogin) {
    recordFailedLogin(username);
    logLoginActivity(username, false, ip, 'Email not verified');
    return res.status(403).json({ error: 'Email not verified. Check your email for verification code.' });
  }

  if (!user.emailVerified && allowUnverifiedLogin) {
    logLoginActivity(username, true, ip, 'Login allowed with ALLOW_UNVERIFIED_LOGIN=true');
  }

  try {
    // Compare passwords using bcrypt
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      recordFailedLogin(username);
      logLoginActivity(username, false, ip, 'Invalid password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Success! Clear failed attempts
    clearFailedAttempts(username);
    
    // Update user login stats
    user.lastLogin = new Date().toISOString();
    user.loginCount = (user.loginCount || 0) + 1;
    saveUsers(USERS);

    const role = resolveUserRole(user);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, {
      id: user.id,
      username: user.username,
      name: user.name,
      company: user.company,
      role,
      isAdmin: role === 'admin' || role === 'super-admin',
    });

    // Create session tracking
    const userAgent = req.headers['user-agent'] || '';
    createUserSession(user.id, token, ip, userAgent);

    logLoginActivity(username, true, ip, 'Successful login');

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        company: user.company,
        role,
        isAdmin: role === 'admin' || role === 'super-admin',
      },
    });
  } catch (err) {
    recordFailedLogin(username);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/verify', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ valid: false });
  }
  const sessionUser = sessions.get(token);
  const dbUser = USERS.find(u => u.id === sessionUser.id);
  const role = resolveUserRole(dbUser || sessionUser);
  sessionUser.role = role;
  sessionUser.isAdmin = role === 'admin' || role === 'super-admin';
  res.json({ valid: true, user: sessionUser });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) sessions.delete(token);
  res.json({ success: true });
});

// ─── Session Management ──────────────────────────────────────────────────────

app.get('/api/sessions', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const userSess = getUserSessions(userId);
  
  // Get current token to mark as current
  const currentToken = req.headers.authorization?.replace('Bearer ', '');
  
  const sessionsData = userSess.map(s => ({
    sessionId: s.sessionId,
    browser: s.browser,
    os: s.os,
    ip: s.ip,
    loginTime: s.loginTime,
    lastActivity: s.lastActivity,
    isCurrent: s.token === currentToken
  }));
  
  res.json(sessionsData);
});

app.delete('/api/sessions/:sessionId', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const { sessionId } = req.params;
  
  // Don't allow deleting current session from this endpoint
  const currentToken = req.headers.authorization?.replace('Bearer ', '');
  const userSess = getUserSessions(userId);
  const sessionToDelete = userSess.find(s => s.sessionId === sessionId);
  
  if (sessionToDelete && sessionToDelete.token === currentToken) {
    return res.status(400).json({ error: 'Cannot delete current session this way. Use logout instead.' });
  }
  
  if (logoutSession(userId, sessionId)) {
    res.json({ success: true, message: 'Session logged out' });
  } else {
    res.status(404).json({ error: 'Session not found' });
  }
});

app.post('/api/sessions/logout-others', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const currentToken = req.headers.authorization?.replace('Bearer ', '');
  const userSess = getUserSessions(userId);
  
  const currentSession = userSess.find(s => s.token === currentToken);
  if (currentSession) {
    logoutOtherSessions(userId, currentSession.sessionId);
    res.json({ success: true, message: 'All other sessions logged out' });
  } else {
    res.status(400).json({ error: 'Current session not found' });
  }
});

// ─── Password Reset / Forgot Password ────────────────────────────────────────

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = USERS.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'Email not found' });

  // Generate reset token (simple 6-digit code)
  const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
  const resetExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

  user.resetToken = resetCode;
  user.resetExpires = resetExpires;
  saveUsers(USERS);

  // Send password reset email
  try {
    await sendPasswordResetEmail(email, resetCode);
  } catch (emailErr) {
    console.error('Failed to send reset email:', emailErr.message);
    // Continue even if email fails
  }

  res.json({
    success: true,
    message: 'Password reset code sent to email',
    expiresIn: '15 minutes'
  });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, resetCode, newPassword, confirmPassword } = req.body;

  if (!email || !resetCode || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const user = USERS.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.resetToken !== resetCode) {
    return res.status(400).json({ error: 'Invalid reset code' });
  }

  if (Date.now() > user.resetExpires) {
    return res.status(400).json({ error: 'Reset code expired' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = null;
    user.resetExpires = null;
    saveUsers(USERS);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// ─── User Profile Management (Protected Routes) ─────────────────────────────

app.get('/api/auth/profile', authMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    name: user.name,
    company: user.company,
    createdAt: user.createdAt,
    role: resolveUserRole(user),
    isAdmin: isRoleAllowed(resolveUserRole(user), 'admin'),
  });
});

app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const { name, email, company } = req.body;
  const user = USERS.find(u => u.id === req.user.id);

  if (!user) return res.status(404).json({ error: 'User not found' });

  // Check if email is already taken by another user
  if (email && email !== user.email && USERS.find(u => u.email === email)) {
    return res.status(409).json({ error: 'Email already in use' });
  }

  if (name) user.name = name;
  if (email) user.email = email;
  if (company) user.company = company;

  saveUsers(USERS);

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      name: user.name,
      company: user.company
    }
  });
});

app.put('/api/auth/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const user = USERS.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    const passwordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    saveUsers(USERS);

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Password change failed' });
  }
});

// ─── Admin Endpoints (Admin Only) ────────────────────────────────────────────

// Get all users (admin only)
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const userList = USERS.map(u => ({
    id: u.id,
    username: u.username,
    email: u.email,
    name: u.name,
    company: u.company,
    createdAt: u.createdAt,
    emailVerified: u.emailVerified,
    role: resolveUserRole(u),
    isAdmin: u.isAdmin,
    lastLogin: u.lastLogin,
    loginCount: u.loginCount
  }));
  res.json(userList);
});

// Get user details (admin)
app.get('/api/admin/users/:id', adminMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    name: user.name,
    company: user.company,
    createdAt: user.createdAt,
    emailVerified: user.emailVerified,
    role: resolveUserRole(user),
    isAdmin: user.isAdmin,
    lastLogin: user.lastLogin,
    loginCount: user.loginCount
  });
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', adminMiddleware, (req, res) => {
  const adminUser = USERS.find(u => u.id === req.user.id);
  const userToDelete = USERS.find(u => u.id === parseInt(req.params.id));

  if (!userToDelete) return res.status(404).json({ error: 'User not found' });
  if (userToDelete.id === adminUser.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  const index = USERS.findIndex(u => u.id === parseInt(req.params.id));
  USERS.splice(index, 1);
  saveUsers(USERS);

  res.json({ success: true, message: 'User deleted' });
});

// Make user admin (admin only)
app.put('/api/admin/users/:id/make-admin', superAdminMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.role = 'admin';
  user.isAdmin = true;
  saveUsers(USERS);

  res.json({ success: true, message: 'User is now admin' });
});

// Remove admin (admin only)
app.put('/api/admin/users/:id/remove-admin', superAdminMiddleware, (req, res) => {
  const adminUser = USERS.find(u => u.id === req.user.id);
  const user = USERS.find(u => u.id === parseInt(req.params.id));

  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.id === adminUser.id) {
    return res.status(400).json({ error: 'Cannot remove admin from yourself' });
  }

  user.role = 'viewer';
  user.isAdmin = false;
  saveUsers(USERS);

  res.json({ success: true, message: 'Admin privileges removed' });
});

app.put('/api/admin/users/:id/role', superAdminMiddleware, (req, res) => {
  const { role } = req.body;
  if (!ROLE_LEVELS[role]) {
    return res.status(400).json({ error: 'Invalid role. Use viewer, analyst, admin, or super-admin' });
  }

  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });

  const currentUserId = req.user.id;
  if (user.id === currentUserId && role !== 'super-admin') {
    return res.status(400).json({ error: 'Cannot downgrade your own super-admin role' });
  }

  user.role = role;
  user.isAdmin = role === 'admin' || role === 'super-admin';
  saveUsers(USERS);

  res.json({ success: true, message: `Role updated to ${role}` });
});

// Get login activity (admin only)
app.get('/api/admin/login-activity', adminMiddleware, (req, res) => {
  res.json(loginActivityLog.slice(0, 100)); // Return last 100 entries
});

// Get login activity for specific user (admin)
app.get('/api/admin/login-activity/user/:username', adminMiddleware, (req, res) => {
  const userActivity = loginActivityLog.filter(log => log.username === req.params.username).slice(0, 50);
  res.json(userActivity);
});

// Reset user password (admin only)
app.post('/api/admin/users/:id/reset-password', adminMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    // Generate temporary password
    const tempPassword = crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(tempPassword, 10);
    
    user.password = hashedPassword;
    saveUsers(USERS);

    res.json({ 
      success: true, 
      message: 'Password reset successfully',
      tempPassword: tempPassword  // DEMO: In production, send via email
    });
  } catch (err) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// ─── Protected Routes (all below use auth) ──────────────────────────────────

app.use('/api/status', authMiddleware);
app.use('/api/devices', authMiddleware);
app.use('/api/logs', authMiddleware);
app.use('/api/honeypot', authMiddleware);
app.use('/api/phishing', authMiddleware);
app.use('/api/killswitch', authMiddleware);
app.use('/api/remediation', authMiddleware);
app.use('/api/threats', authMiddleware);
app.use('/api/settings', authMiddleware);
app.use('/api/scan', authMiddleware);
app.use('/api/alerts', authMiddleware);
app.use('/api/live-feed', authMiddleware);

// ─── Status ─────────────────────────────────────────────────────────────────

app.get('/api/status', (_req, res) => {
  const onlineDevices = devices.filter(d => d.status === 'online').length;
  systemStatus.devicesOnline = onlineDevices;
  systemStatus.devicesTotal = devices.length;
  res.json(systemStatus);
});

// ─── Devices — Full CRUD ────────────────────────────────────────────────────

app.get('/api/devices', (_req, res) => {
  res.json(devices);
});

app.get('/api/devices/:id', (req, res) => {
  const device = devices.find(d => d.id === parseInt(req.params.id));
  if (!device) return res.status(404).json({ error: 'Device not found' });
  res.json(device);
});

app.post('/api/devices', requireRole('analyst'), (req, res) => {
  const { name, type, ip } = req.body;
  const newDevice = {
    id: nextDeviceId++,
    name: name || `Device-${nextDeviceId}`,
    type: type || 'laptop',
    ip: ip || `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
    status: 'online',
    lastThreat: 'None',
    safety: Math.floor(Math.random() * 15) + 85,
    addedAt: new Date().toISOString().split('T')[0],
  };
  devices.unshift(newDevice);
  saveCollection(DEVICES_FILE, devices);
  res.status(201).json(newDevice);
});

app.put('/api/devices/:id', requireRole('analyst'), (req, res) => {
  const device = devices.find(d => d.id === parseInt(req.params.id));
  if (!device) return res.status(404).json({ error: 'Device not found' });

  const { name, type, ip, status } = req.body;
  if (name !== undefined) device.name = name;
  if (type !== undefined) device.type = type;
  if (ip !== undefined) device.ip = ip;
  if (status !== undefined) device.status = status;

  saveCollection(DEVICES_FILE, devices);
  res.json(device);
});

app.patch('/api/devices/:id/toggle', requireRole('analyst'), (req, res) => {
  const device = devices.find(d => d.id === parseInt(req.params.id));
  if (!device) return res.status(404).json({ error: 'Device not found' });

  device.status = device.status === 'online' ? 'offline' : 'online';
  saveCollection(DEVICES_FILE, devices);
  res.json(device);
});

app.delete('/api/devices/:id', requireRole('analyst'), (req, res) => {
  const index = devices.findIndex(d => d.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Device not found' });

  const removed = devices.splice(index, 1)[0];
  saveCollection(DEVICES_FILE, devices);
  res.json({ success: true, removed });
});

// ─── Logs ───────────────────────────────────────────────────────────────────

app.get('/api/logs', (_req, res) => {
  res.json(logs);
});

app.post('/api/logs', requireRole('analyst'), (req, res) => {
  const { time, device, event, summary, action, severity } = req.body;
  const newLog = {
    id: nextLogId++,
    time: time || new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
    device: device || 'Unknown',
    event: event || 'System event',
    summary: summary || 'No summary',
    action: action || 'Logged',
    severity: severity || 'low',
  };
  logs.unshift(newLog);
  saveCollection(LOGS_FILE, logs);
  res.status(201).json(newLog);
});

app.delete('/api/logs/:id', requireRole('analyst'), (req, res) => {
  const index = logs.findIndex(l => l.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Log not found' });
  logs.splice(index, 1);
  saveCollection(LOGS_FILE, logs);
  res.json({ success: true });
});

// ─── Honeypot ───────────────────────────────────────────────────────────────

app.get('/api/honeypot', (_req, res) => {
  res.json(honeypotData);
});

app.post('/api/honeypot/deploy', (req, res) => {
  const fileNames = [
    'salary-report-2025.xlsx', 'admin-passwords.txt', 'employee-ssn.csv',
    'bank-statement-march.pdf', 'confidential-memo.docx', 'crypto-wallet-keys.json',
  ];
  const newDecoy = {
    id: nextDecoyId++,
    name: req.body.name || fileNames[Math.floor(Math.random() * fileNames.length)],
    modified: 'just now',
    status: 'ACTIVE',
  };
  honeypotData.decoys.push(newDecoy);
  res.status(201).json(newDecoy);
});

app.post('/api/honeypot/trigger', (_req, res) => {
  honeypotData.count++;
  const newEvent = {
    id: nextHoneypotEventId++,
    file: `decoy-file-${honeypotData.count}.pdf`,
    time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
    detail: `Accessed by IP ${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)} • Trapped`,
  };
  honeypotData.events.unshift(newEvent);
  res.json({ count: honeypotData.count, event: newEvent });
});

// ─── Phishing Check ─────────────────────────────────────────────────────────

app.post('/api/phishing/check', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  const lowerUrl = url.toLowerCase();
  const isPhishing = PHISHING_PATTERNS.some(pattern => lowerUrl.includes(pattern));
  const suspiciousTLDs = ['.xyz', '.top', '.buzz', '.click', '.loan', '.work'];
  const hasSuspiciousTLD = suspiciousTLDs.some(tld => lowerUrl.endsWith(tld));
  const noHttps = !lowerUrl.startsWith('https://');
  const dangerous = isPhishing || hasSuspiciousTLD;

  res.json({
    url,
    dangerous,
    confidence: dangerous ? Math.floor(Math.random() * 10) + 90 : Math.floor(Math.random() * 20) + 5,
    reason: dangerous
      ? 'This link matches known phishing patterns. It impersonates a legitimate service and is known to steal credentials.'
      : 'This link appears safe. No known phishing indicators detected.',
    details: { httpsValid: !noHttps, knownPattern: isPhishing, suspiciousTLD: hasSuspiciousTLD },
  });
});

// ─── Threats — Detail ───────────────────────────────────────────────────────

app.get('/api/threats', (_req, res) => {
  res.json(threats);
});

app.get('/api/threats/:id', (req, res) => {
  const threat = threats.find(t => t.id === parseInt(req.params.id));
  if (!threat) return res.status(404).json({ error: 'Threat not found' });
  res.json(threat);
});

// ─── Kill Switch — Real Network Isolation ───────────────────────────────────

app.post('/api/killswitch', requireRole('admin'), async (req, res) => {
  const reason = req.body.reason || 'Manual kill switch activation';

  // Mark ALL online devices as isolated
  let isolated = 0;
  devices.forEach(d => {
    if (d.status === 'online') {
      d.status = 'offline';
      d.lastThreat = 'Isolated by kill switch';
      d.safety = 0;
      isolated++;
    }
  });
  if (devices.length > 0) saveCollection(DEVICES_FILE, devices);

  const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
  logs.unshift({
    id: nextLogId++,
    time: timeStr,
    device: 'CyberMind',
    event: 'Kill Switch Activated',
    summary: `Network isolation triggered: ${reason}. ${isolated} device(s) isolated.`,
    action: 'ISOLATED',
    severity: 'critical',
  });
  saveCollection(LOGS_FILE, logs);

  // Also call Flask isolation endpoint
  try {
    await fetch('http://localhost:5000/api/isolation/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer killswitch', 'X-User-Role': 'admin' },
      body: JSON.stringify({ reason }),
    });
  } catch (_) { /* Flask may not be running */ }

  systemStatus.lastThreatDetected = 'just now';
  res.json({
    success: true,
    message: `Kill switch activated. ${isolated} device(s) isolated from network.`,
    isolated_count: isolated,
  });
});

// Release kill switch
app.post('/api/killswitch/release', requireRole('admin'), async (req, res) => {
  devices.forEach(d => { if (d.lastThreat === 'Isolated by kill switch') { d.status = 'online'; d.lastThreat = 'None'; d.safety = 95; } });
  saveCollection(DEVICES_FILE, devices);
  try {
    await fetch('http://localhost:5000/api/isolation/deactivate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer admin', 'X-User-Role': 'admin' },
      body: JSON.stringify({ authorization_code: 'manual' }),
    });
  } catch (_) { }
  res.json({ success: true, message: 'Network isolation released.' });
});

// ─── Remediation Playbooks — Real ───────────────────────────────────────────

app.post('/api/remediation', requireRole('analyst'), (req, res) => {
  const { playbook, ip, device_id } = req.body;
  const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
  const detectedAt = new Date().toISOString();

  // Playbook 1: Block suspicious IP
  if (playbook === 1 || req.body.action === 'block_ip') {
    const targetIp = ip || 'unknown';
    const alreadyBlocked = ipBlocklist.some(b => b.ip === targetIp && b.status === 'blocked');
    if (!alreadyBlocked && targetIp !== 'unknown') {
      ipBlocklist.unshift({
        id: nextBlockId++, ip: targetIp, attackType: 'suspicious_activity',
        label: 'Manually Blocked', severity: 'high', status: 'blocked',
        detectedAt, timeStr, payload: 'Manual block', source_port: 0, target_port: 0, block_method: 'manual',
      });
      if (ipBlocklist.length > 500) ipBlocklist = ipBlocklist.slice(0, 500);
      saveBlocklist(ipBlocklist);
    }
    logs.unshift({ id: nextLogId++, time: timeStr, device: 'CyberMind', event: 'IP Blocked',
      summary: `Manually blocked ${targetIp}`, action: 'Blocked', severity: 'high' });
    saveCollection(LOGS_FILE, logs);
    systemStatus.lastThreatDetected = 'just now';
    return res.json({ action: 'block_ip', message: `IP ${targetIp} blocked successfully`, success: true });
  }

  // Playbook 2: Quarantine device — mark offline + block its IP
  if (playbook === 2 || req.body.action === 'quarantine') {
    const targetIp = ip || 'unknown';
    const device = devices.find(d => d.ip === targetIp || String(d.id) === String(device_id));
    if (device) {
      device.status = 'offline'; device.lastThreat = 'Quarantined'; device.safety = 0;
      saveCollection(DEVICES_FILE, devices);
    }
    if (targetIp !== 'unknown') {
      const alreadyBlocked = ipBlocklist.some(b => b.ip === targetIp && b.status === 'blocked');
      if (!alreadyBlocked) {
        ipBlocklist.unshift({
          id: nextBlockId++, ip: targetIp, attackType: 'suspicious_activity',
          label: 'Device Quarantined', severity: 'high', status: 'blocked',
          detectedAt, timeStr, payload: 'Quarantine', source_port: 0, target_port: 0, block_method: 'quarantine',
        });
        saveBlocklist(ipBlocklist);
      }
    }
    logs.unshift({ id: nextLogId++, time: timeStr, device: device?.name || targetIp,
      event: 'Device Quarantined', summary: `Device ${device?.name || targetIp} isolated from network`,
      action: 'QUARANTINED', severity: 'high' });
    saveCollection(LOGS_FILE, logs);
    return res.json({ action: 'quarantine', message: `Device ${device?.name || targetIp} quarantined`, success: true });
  }

  res.json({ action: 'unknown', message: 'Unknown playbook', success: false });
});

// ─── Log Translation — Real (Flask Ollama + rule fallback) ─────────────────

app.post('/api/logs/translate', async (req, res) => {
  const { rawLog } = req.body;
  if (!rawLog) return res.status(400).json({ error: 'rawLog required' });

  // Try Flask Ollama translation first
  try {
    const flaskRes = await fetch('http://localhost:5000/api/traffic/translate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        threat_type: rawLog, severity: 'medium', confidence: 0.7,
        source_ip: 'unknown', matched_signature: rawLog,
        mitigation: 'Investigate and block if malicious'
      }),
    });
    if (flaskRes.ok) {
      const data = await flaskRes.json();
      return res.json({ rawLog, translation: data.translation?.plain_english || data.translation || rawLog });
    }
  } catch (_) { }

  // Rule-based fallback
  const lower = rawLog.toLowerCase();
  let translation = `Security event detected: ${rawLog}`;
  if (lower.includes('brute') || lower.includes('login') || lower.includes('password'))
    translation = 'Someone is repeatedly trying to guess a password. This is a brute-force attack — block the source IP immediately.';
  else if (lower.includes('scan') || lower.includes('nmap') || lower.includes('port'))
    translation = 'An attacker is scanning your network ports to find weaknesses. This reconnaissance precedes targeted attacks.';
  else if (lower.includes('ddos') || lower.includes('flood') || lower.includes('syn'))
    translation = 'Your network is being flooded with traffic to overwhelm it. This is a Denial of Service attack.';
  else if (lower.includes('sql') || lower.includes('inject'))
    translation = 'An attacker is injecting malicious SQL code into your database. This can steal or destroy your data.';
  else if (lower.includes('malware') || lower.includes('exploit') || lower.includes('shell'))
    translation = 'Malicious software or exploit code detected. Isolate the affected device immediately.';

  res.json({ rawLog, translation });
});

// ─── Settings ───────────────────────────────────────────────────────────────

app.get('/api/settings', (_req, res) => {
  res.json(settings);
});

app.put('/api/settings', requireRole('admin'), (req, res) => {
  const allowed = [
    'companyName', 'autoBlockThreats', 'notificationsEnabled',
    'emailAlertsEnabled', 'alertEmail', 'alertOnHigh', 'alertOnMedium',
    'alertOnLow', 'darkMode', 'autoScanInterval', 'retentionDays',
  ];
  allowed.forEach(key => {
    if (req.body[key] !== undefined) settings[key] = req.body[key];
  });
  res.json(settings);
});

// ─── Network Scan ───────────────────────────────────────────────────────────

app.post('/api/scan', requireRole('analyst'), (_req, res) => {
  const scanResults = devices.map(device => ({
    deviceId: device.id,
    deviceName: device.name,
    ip: device.ip,
    status: device.status,
    openPorts: device.status === 'online'
      ? [22, 80, 443].filter(() => Math.random() > 0.3).concat(Math.random() > 0.7 ? [3389] : [])
      : [],
    vulnerabilities: device.status === 'online'
      ? [
        Math.random() > 0.5 ? { severity: 'low', description: 'Outdated SSL certificate' } : null,
        Math.random() > 0.7 ? { severity: 'medium', description: 'Open RDP port detected' } : null,
        Math.random() > 0.85 ? { severity: 'high', description: 'Unpatched CVE-2024-3094' } : null,
      ].filter(Boolean)
      : [],
    lastScan: new Date().toISOString(),
    scanDuration: `${(Math.random() * 3 + 1).toFixed(1)}s`,
  }));

  const totalVulns = scanResults.reduce((sum, r) => sum + r.vulnerabilities.length, 0);

  logs.unshift({
    id: nextLogId++,
    time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
    device: 'System',
    event: 'Network Scan',
    summary: `Scan complete: ${totalVulns} vulnerabilities found across ${devices.length} devices`,
    action: 'Completed',
    severity: totalVulns > 2 ? 'high' : 'low',
  });

  res.json({ results: scanResults, totalVulnerabilities: totalVulns, scannedAt: new Date().toISOString() });
});

// ─── Alert Configuration ────────────────────────────────────────────────────

app.get('/api/alerts/config', (_req, res) => {
  res.json({
    emailAlertsEnabled: settings.emailAlertsEnabled,
    alertEmail: settings.alertEmail,
    alertOnHigh: settings.alertOnHigh,
    alertOnMedium: settings.alertOnMedium,
    alertOnLow: settings.alertOnLow,
  });
});

app.put('/api/alerts/config', requireRole('admin'), (req, res) => {
  const { emailAlertsEnabled, alertEmail, alertOnHigh, alertOnMedium, alertOnLow } = req.body;
  if (emailAlertsEnabled !== undefined) settings.emailAlertsEnabled = emailAlertsEnabled;
  if (alertEmail !== undefined) settings.alertEmail = alertEmail;
  if (alertOnHigh !== undefined) settings.alertOnHigh = alertOnHigh;
  if (alertOnMedium !== undefined) settings.alertOnMedium = alertOnMedium;
  if (alertOnLow !== undefined) settings.alertOnLow = alertOnLow;

  res.json({
    emailAlertsEnabled: settings.emailAlertsEnabled,
    alertEmail: settings.alertEmail,
    alertOnHigh: settings.alertOnHigh,
    alertOnMedium: settings.alertOnMedium,
    alertOnLow: settings.alertOnLow,
  });
});

// ─── Live Feed ──────────────────────────────────────────────────────────────

app.get('/api/live-feed', (_req, res) => {
  // Return the most recent real event from the blocklist or logs
  if (ipBlocklist.length > 0) {
    const latest = ipBlocklist[0];
    const timeAgo = formatTimeAgo(latest.detectedAt);
    const typeMap = {
      brute_force: 'Brute force attack',
      port_scan: 'Port scan',
      ddos: 'DDoS flood',
      sql_injection: 'SQL injection attempt',
      malware: 'Malware payload',
      recon: 'Reconnaissance activity',
      suspicious_activity: 'Suspicious activity',
    };
    const label = typeMap[latest.attackType] || 'Attack';
    return res.json({
      type: 'warning',
      text: `${label} from ${latest.ip} — blocked ${timeAgo}`,
      timestamp: latest.detectedAt,
    });
  }
  if (logs.length > 0) {
    const latest = logs[0];
    return res.json({ type: 'info', text: latest.summary || latest.event, timestamp: latest.time });
  }
  res.json({ type: 'info', text: 'CyberMind is monitoring your network. No threats detected yet.', timestamp: new Date().toISOString() });
});

function formatTimeAgo(isoTimestamp) {
  if (!isoTimestamp) return 'recently';
  const diff = Math.floor((Date.now() - new Date(isoTimestamp).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// ─── Attack Detection & IP Blocklist (Demo Endpoints) ───────────────────────

// POST /api/detect-attack — receives attack payloads (from demo script or real traffic)
// No auth required so the professor's demo works even without login
app.post('/api/detect-attack', (req, res) => {
  const {
    payload = '',
    threat_type: rawType = '',
    source_port = 0,
    target_port = 80,
    message = '',
  } = req.body || {};

  // Determine real source IP (supports X-Forwarded-For from proxy / curl)
  const forwarded = req.headers['x-forwarded-for'] || '';
  const sourceIp = forwarded.split(',')[0].trim() || req.socket.remoteAddress || req.ip || '127.0.0.1';

  // Classify the attack
  const attackType   = classifyAttack(payload + ' ' + message, rawType);
  const severity     = getSeverity(attackType);
  const detectedAt   = new Date().toISOString();
  const timeStr      = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });

  // Human-readable label map
  const typeLabels = {
    brute_force:        'Brute Force Attack',
    port_scan:          'Port Scan',
    sql_injection:      'SQL Injection Attempt',
    xss:                'Cross-Site Scripting (XSS)',
    ddos:               'DDoS / Flood Attack',
    malware:            'Malware / Exploit Payload',
    recon:              'Reconnaissance Activity',
    suspicious_activity:'Suspicious Activity',
  };
  const label = typeLabels[attackType] || 'Unknown Attack';

  // Check if IP already blocked
  const alreadyBlocked = ipBlocklist.some(b => b.ip === sourceIp && b.status === 'blocked');

  // Create blocklist record
  const blockRecord = {
    id: nextBlockId++,
    ip: sourceIp,
    attackType,
    label,
    severity,
    payload: payload.slice(0, 200),
    message: message.slice(0, 200),
    sourcePort: source_port,
    targetPort: target_port,
    status: 'blocked',
    detectedAt,
    timeStr,
    alreadyBlocked,
  };

  if (!alreadyBlocked) {
    ipBlocklist.unshift(blockRecord);
    // Keep last 500 records
    if (ipBlocklist.length > 500) ipBlocklist = ipBlocklist.slice(0, 500);
    saveBlocklist(ipBlocklist);
  }

  // Also push to the main security logs so dashboard shows it
  logs.unshift({
    id: nextLogId++,
    time: timeStr,
    device: 'CyberMind-Sentinel',
    event: label,
    summary: `Attack detected from ${sourceIp} — ${severity.toUpperCase()} severity. IP ${alreadyBlocked ? 'was already blocked' : 'auto-blocked'}.`,
    action: 'Blocked',
    severity,
  });
  saveCollection(LOGS_FILE, logs);

  // Add to active threats list (deduplicated by sourceIp)
  if (!alreadyBlocked) {
    const existingThreat = threats.find(t => t.sourceIp === sourceIp && t.status === 'active');
    if (!existingThreat) {
      threats.unshift({
        id: nextThreatId++,
        title: label,
        severity,
        status: 'active',
        sourceIp,
        sourceCountry: 'Unknown',
        targetDevice: 'CyberMind Host',
        detectedAt,
        attempts: 1,
        description: `${label} detected from ${sourceIp} on port ${target_port}.`,
        timeline: [
          { time: timeStr, event: `${label} detected` },
          { time: timeStr, event: `IP ${sourceIp} auto-blocked` },
        ],
        recommendations: [
          `Block all traffic from ${sourceIp}`,
          'Review firewall rules',
          'Check for related activity in logs',
        ],
      });
    } else {
      existingThreat.attempts = (existingThreat.attempts || 1) + 1;
      existingThreat.timeline.push({ time: timeStr, event: `Repeated attempt #${existingThreat.attempts}` });
    }
  }

  // Update system status
  systemStatus.threatsActive = Math.min(systemStatus.threatsActive + (alreadyBlocked ? 0 : 1), 99);
  systemStatus.safetyScore   = Math.max(systemStatus.safetyScore - (alreadyBlocked ? 0 : 0.5), 60);
  systemStatus.lastThreatDetected = 'just now';

  console.log(`[DETECT] ${severity.toUpperCase()} ${label} from ${sourceIp} — ${alreadyBlocked ? 'already blocked' : 'BLOCKED'}`);

  res.json({
    success: true,
    message: alreadyBlocked ? `IP ${sourceIp} was already in blocklist` : `Attack detected & IP ${sourceIp} auto-blocked`,
    detection: blockRecord,
    total_blocked: ipBlocklist.length,
  });
});

// GET /api/blocklist — retrieve current IP blocklist with stats
app.get('/api/blocklist', (req, res) => {
  const total = ipBlocklist.length;
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byType = {};

  ipBlocklist.forEach(b => {
    if (bySeverity[b.severity] !== undefined) bySeverity[b.severity]++;
    byType[b.attackType] = (byType[b.attackType] || 0) + 1;
  });

  res.json({
    total,
    bySeverity,
    byType,
    records: ipBlocklist.slice(0, 100), // last 100
  });
});

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  🛡️  CyberMind Sentinel API running at http://localhost:${PORT}`);
  console.log(`  🔐  Auth: POST /api/auth/login  (admin / cybermind2025)`);
  console.log(`  📡  Endpoints: /api/devices, /api/logs, /api/honeypot, /api/threats, /api/settings`);
  console.log(`  🔑  Kill switch armed at /api/killswitch\n`);
});
