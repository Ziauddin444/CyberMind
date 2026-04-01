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

// ─── In-Memory Data ─────────────────────────────────────────────────────────

// Auth
let USERS = loadUsers();
const sessions = new Map();

// Failed login attempts tracking (for rate limiting)
const failedLoginAttempts = new Map(); // key: username, value: { count, blockUntil }

// Login activity log
let loginActivityLog = [];

// Email verification tokens
const emailVerificationTokens = new Map(); // key: token, value: { email, expiresAt }

// User sessions tracking - key: userId, value: [{ sessionId, token, deviceInfo, ip, loginTime, lastActivity }]
const userSessions = new Map();

// Devices
let devices = [
  { id: 1, name: 'MacBook-Air', type: 'laptop', ip: '192.168.1.10', status: 'online', lastThreat: 'None', safety: 96, addedAt: '2025-01-15' },
  { id: 2, name: 'Windows-Server', type: 'server', ip: '192.168.1.20', status: 'online', lastThreat: 'Brute force attempt', safety: 71, addedAt: '2025-01-10' },
  { id: 3, name: 'POS-Terminal-1', type: 'iot', ip: '192.168.1.30', status: 'offline', lastThreat: 'None', safety: 100, addedAt: '2025-02-01' },
];
let nextDeviceId = 4;

// Logs
let logs = [
  { id: 1, time: '12:41', device: 'MacBook-Air', event: 'Failed login', summary: 'Brute-force attempt from Russia', action: 'Blocked', severity: 'high' },
  { id: 2, time: '12:39', device: 'Windows-Server', event: 'File created', summary: 'Suspicious .exe file downloaded', action: 'Quarantined', severity: 'critical' },
  { id: 3, time: '12:33', device: 'POS-Terminal-1', event: 'USB inserted', summary: 'Unknown USB device connected', action: 'Monitored', severity: 'medium' },
  { id: 4, time: '12:20', device: 'MacBook-Air', event: 'App installed', summary: 'New application installed: Slack', action: 'Allowed', severity: 'low' },
  { id: 5, time: '11:55', device: 'Windows-Server', event: 'Port scan', summary: 'External port scan detected from 45.33.32.156', action: 'Blocked', severity: 'high' },
];
let nextLogId = 6;

// Honeypot
let honeypotData = {
  count: 14,
  events: [
    { id: 1, file: 'invoice.docm.exe', time: '11:04', detail: 'Accessed by IP 194.156.87.22 • Trapped' },
    { id: 2, file: 'passwords.xlsx', time: '10:51', detail: 'Accessed by unknown user • Trapped' },
  ],
  decoys: [
    { id: 1, name: 'tax-return-2024.pdf', modified: '2hrs ago', status: 'ACTIVE' },
    { id: 2, name: 'client-contracts.docx', modified: '5hrs ago', status: 'ACTIVE' },
  ],
};
let nextHoneypotEventId = 3;
let nextDecoyId = 3;

// Threats (detailed)
let threats = [
  {
    id: 1,
    title: 'Brute Force Login Attack',
    severity: 'high',
    status: 'active',
    sourceIp: '185.53.177.54',
    sourceCountry: 'Romania',
    targetDevice: 'Windows-Server',
    detectedAt: '2025-02-18 12:41:09',
    attempts: 14,
    description: 'Multiple failed login attempts targeting the Administrator account from a known malicious IP address.',
    timeline: [
      { time: '12:41:09', event: 'First failed login detected' },
      { time: '12:41:12', event: '5 rapid attempts in 3 seconds' },
      { time: '12:41:15', event: 'AI flagged as brute force pattern' },
      { time: '12:41:16', event: 'IP automatically blocked' },
      { time: '12:41:17', event: 'Alert sent to admin' },
    ],
    recommendations: [
      'Enable multi-factor authentication',
      'Consider geo-blocking Eastern European IPs',
      'Review password policy for Administrator account',
      'Enable account lockout after 5 failed attempts',
    ],
  },
  {
    id: 2,
    title: 'Suspicious File Download',
    severity: 'critical',
    status: 'active',
    sourceIp: '91.234.99.12',
    sourceCountry: 'Unknown',
    targetDevice: 'MacBook-Air',
    detectedAt: '2025-02-18 12:39:22',
    attempts: 1,
    description: 'A file disguised as a PDF invoice was downloaded. File extension analysis reveals it is an executable (.pdf.exe).',
    timeline: [
      { time: '12:39:22', event: 'File download initiated via email link' },
      { time: '12:39:23', event: 'AI detected double extension (.pdf.exe)' },
      { time: '12:39:23', event: 'File quarantined before execution' },
      { time: '12:39:24', event: 'Hash matched known malware signature' },
    ],
    recommendations: [
      'Train employees on phishing email identification',
      'Block executable downloads from email links',
      'Enable real-time file scanning',
      'Review email filtering rules',
    ],
  },
];
let nextThreatId = 3;

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

// System Status
let systemStatus = {
  status: 'online',
  safetyScore: 98.4,
  aiConfidence: 92,
  threatsActive: 2,
  lastThreatDetected: '17s ago',
};

// Phishing patterns
const PHISHING_PATTERNS = [
  'secure-bank-login', 'account-verify', 'paypa1', 'login-update',
  'free-prize', 'claim-bonus', 'urgent-action', 'suspended-account',
  'microsoft-alert', 'apple-id-lock', 'netflix-payment', 'amazon-security',
];

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
  req.user = sessions.get(token);
  next();
}

// Admin middleware
function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    const user = USERS.find(u => u.id === req.user.id);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
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
  if (!user.emailVerified) {
    recordFailedLogin(username);
    logLoginActivity(username, false, ip, 'Email not verified');
    return res.status(403).json({ error: 'Email not verified. Check your email for verification code.' });
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

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { id: user.id, username: user.username, name: user.name, company: user.company, isAdmin: user.isAdmin });

    // Create session tracking
    const userAgent = req.headers['user-agent'] || '';
    createUserSession(user.id, token, ip, userAgent);

    logLoginActivity(username, true, ip, 'Successful login');

    res.json({
      token,
      user: { id: user.id, username: user.username, name: user.name, company: user.company, isAdmin: user.isAdmin },
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
  res.json({ valid: true, user: sessions.get(token) });
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
    createdAt: user.createdAt
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
app.put('/api/admin/users/:id/make-admin', adminMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.isAdmin = true;
  saveUsers(USERS);

  res.json({ success: true, message: 'User is now admin' });
});

// Remove admin (admin only)
app.put('/api/admin/users/:id/remove-admin', adminMiddleware, (req, res) => {
  const adminUser = USERS.find(u => u.id === req.user.id);
  const user = USERS.find(u => u.id === parseInt(req.params.id));

  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.id === adminUser.id) {
    return res.status(400).json({ error: 'Cannot remove admin from yourself' });
  }

  user.isAdmin = false;
  saveUsers(USERS);

  res.json({ success: true, message: 'Admin privileges removed' });
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

app.post('/api/devices', (req, res) => {
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
  res.status(201).json(newDevice);
});

app.put('/api/devices/:id', (req, res) => {
  const device = devices.find(d => d.id === parseInt(req.params.id));
  if (!device) return res.status(404).json({ error: 'Device not found' });

  const { name, type, ip, status } = req.body;
  if (name !== undefined) device.name = name;
  if (type !== undefined) device.type = type;
  if (ip !== undefined) device.ip = ip;
  if (status !== undefined) device.status = status;

  res.json(device);
});

app.patch('/api/devices/:id/toggle', (req, res) => {
  const device = devices.find(d => d.id === parseInt(req.params.id));
  if (!device) return res.status(404).json({ error: 'Device not found' });

  device.status = device.status === 'online' ? 'offline' : 'online';
  res.json(device);
});

app.delete('/api/devices/:id', (req, res) => {
  const index = devices.findIndex(d => d.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Device not found' });

  const removed = devices.splice(index, 1)[0];
  res.json({ success: true, removed });
});

// ─── Logs ───────────────────────────────────────────────────────────────────

app.get('/api/logs', (_req, res) => {
  res.json(logs);
});

app.post('/api/logs', (req, res) => {
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
  res.status(201).json(newLog);
});

app.delete('/api/logs/:id', (req, res) => {
  const index = logs.findIndex(l => l.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: 'Log not found' });
  logs.splice(index, 1);
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

// ─── Kill Switch ────────────────────────────────────────────────────────────

app.post('/api/killswitch', (req, res) => {
  const deviceId = req.body.deviceId || 2;
  const device = devices.find(d => d.id === deviceId);

  if (device) {
    device.status = 'offline';
    device.lastThreat = 'Ransomware — ISOLATED';
    device.safety = 0;
  }

  logs.unshift({
    id: nextLogId++,
    time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
    device: device ? device.name : 'Unknown',
    event: 'Kill switch',
    summary: 'Mass encryption halted — device isolated',
    action: 'ISOLATED',
    severity: 'critical',
  });

  systemStatus.threatsActive = Math.max(0, systemStatus.threatsActive - 1);
  res.json({ success: true, message: 'Device isolated. Ransomware contained.', device });
});

// ─── Remediation Playbooks ──────────────────────────────────────────────────

app.post('/api/remediation', (req, res) => {
  const { playbook } = req.body;
  const results = {
    1: { action: 'block_ip', message: 'IP 185.53.177.54 successfully blocked', success: true },
    2: { action: 'quarantine', message: 'Device isolated from network', success: true },
    3: { action: 'deep_scan', message: 'Deep scan started on all devices', success: true },
  };

  const result = results[playbook] || { action: 'unknown', message: 'Unknown playbook', success: false };

  if (result.success) {
    logs.unshift({
      id: nextLogId++,
      time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
      device: 'System',
      event: `Playbook ${playbook}`,
      summary: result.message,
      action: 'Executed',
      severity: 'low',
    });
  }

  res.json(result);
});

// ─── Log Translation ────────────────────────────────────────────────────────

app.post('/api/logs/translate', (req, res) => {
  const { rawLog } = req.body;
  const translation = 'An attacker from an unknown IP address in Eastern Europe is trying to brute-force your administrator account. They tried 14 different passwords in under a minute.';
  res.json({ rawLog, translation });
});

// ─── Settings ───────────────────────────────────────────────────────────────

app.get('/api/settings', (_req, res) => {
  res.json(settings);
});

app.put('/api/settings', (req, res) => {
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

app.post('/api/scan', (_req, res) => {
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

app.put('/api/alerts/config', (req, res) => {
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
  const liveMessages = [
    { type: 'info', text: 'New login from trusted device' },
    { type: 'warning', text: 'Outbound connection to suspicious domain blocked' },
    { type: 'info', text: 'Scheduled backup completed successfully' },
    { type: 'success', text: 'Firewall rules updated automatically' },
    { type: 'warning', text: 'Port scan detected from external IP — blocked' },
    { type: 'info', text: 'SSL certificate renewal verified' },
  ];
  res.json(liveMessages[Math.floor(Math.random() * liveMessages.length)]);
});

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  🛡️  CyberMind Sentinel API running at http://localhost:${PORT}`);
  console.log(`  🔐  Auth: POST /api/auth/login  (admin / cybermind2025)`);
  console.log(`  📡  Endpoints: /api/devices, /api/logs, /api/honeypot, /api/threats, /api/settings`);
  console.log(`  🔑  Kill switch armed at /api/killswitch\n`);
});
