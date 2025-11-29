// authService: attempts to use a backend auth API if available, otherwise falls back to in-app/localStorage behavior
const API_BASE = (typeof window !== 'undefined' && window.location && window.location.hostname === 'localhost') ? 'http://localhost:4000' : '';

// In-memory fallback users (legacy behavior)
const users = [
  { email: 'admin@heritage.com', password: 'admin123', role: 'admin', dashboard: '/admin/enthusiast-dashboard' },
  { email: 'user@heritage.com', password: 'user123', role: 'user', dashboard: '/admin/user-dashboard' },
  { email: 'creator@heritage.com', password: 'creator123', role: 'content-creator', dashboard: '/admin/content-creator-dashboard' }
];

async function tryFetchJson(url, options) {
  try {
    const res = await fetch(url, options);
    const json = await res.json();
    return { ok: res.ok, json };
  } catch (e) {
    return { ok: false, json: null, error: e };
  }
}

export const authenticateUser = async (email, password) => {
  // Try backend first
  if (API_BASE) {
    const { ok, json } = await tryFetchJson(API_BASE + '/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password })
    });
    if (ok && json && json.success) {
      // persist token and user
      try { localStorage.setItem('authToken', json.token); } catch (e) {}
      const u = { email: json.user.email, role: json.user.role };
      localStorage.setItem('currentUser', JSON.stringify(u));
      return { success: true, user: u };
    }
    // fall through to local fallback if network/auth fails
  }

  // Fallback (legacy local behavior)
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.password === password);
  if (user) {
    localStorage.setItem('currentUser', JSON.stringify({ email: user.email, role: user.role, dashboard: user.dashboard }));
    return { success: true, user: { email: user.email, role: user.role, dashboard: user.dashboard } };
  }
  return { success: false, message: 'Invalid email or password' };
};

export const registerUser = async (email, password, name, role) => {
  // Try backend register
  if (API_BASE) {
    const { ok, json } = await tryFetchJson(API_BASE + '/api/auth/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, name, role })
    });
    if (ok && json && json.success) {
      try { localStorage.setItem('authToken', json.token); } catch (e) {}
      const u = { email: json.user.email, role: json.user.role };
      localStorage.setItem('currentUser', JSON.stringify(u));
      return { success: true, message: json.message, user: u };
    }
    if (json && !json.success) return { success: false, message: json.message };
    // fall through to fallback below if network unavailable
  }

  // Local fallback registration (stores in localStorage)
  const existing = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (existing) return { success: false, message: 'User with this email already exists' };
  if (!email || !password || !name || !role) return { success: false, message: 'All fields are required' };
  if (password.length < 6) return { success: false, message: 'Password must be at least 6 characters long' };

  const getDashboardPath = (userRole) => {
    switch (userRole) {
      case 'admin': return '/admin/enthusiast-dashboard';
      case 'user': return '/admin/user-dashboard';
      case 'content-creator': return '/admin/content-creator-dashboard';
      case 'tour-guide': return '/admin/tour-guide-dashboard';
      default: return '/admin/user-dashboard';
    }
  };

  const newUser = { email: email.toLowerCase(), password, name, role, dashboard: getDashboardPath(role), createdAt: new Date().toISOString() };
  users.push(newUser);
  const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
  registeredUsers.push(newUser);
  localStorage.setItem('registeredUsers', JSON.stringify(registeredUsers));
  return { success: true, message: 'Registration successful! You can now login.', user: { email: newUser.email, name: newUser.name, role: newUser.role, dashboard: newUser.dashboard } };
};

export const loadRegisteredUsers = () => {
  try {
    const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
    registeredUsers.forEach(user => {
      const exists = users.find(u => u.email.toLowerCase() === user.email.toLowerCase());
      if (!exists) users.push(user);
    });
  } catch (e) {
    // ignore
  }
};

// initialize fallback users
try { loadRegisteredUsers(); } catch (e) {}

export const getCurrentUser = () => {
  const user = localStorage.getItem('currentUser');
  return user ? JSON.parse(user) : null;
};

export const logout = () => {
  localStorage.removeItem('currentUser');
  localStorage.removeItem('authToken');
};

export const getPredefinedUsers = () => users.map(u => ({ email: u.email, role: u.role, dashboard: u.dashboard }));

export const rememberCredentials = (email, password) => {
  try { localStorage.setItem('rememberedCredentials', JSON.stringify({ email: email.toLowerCase(), password })); return { success: true }; } catch (e) { return { success: false, message: 'Failed to remember credentials' }; }
};

export const getRememberedCredentials = () => {
  try { const raw = localStorage.getItem('rememberedCredentials'); return raw ? JSON.parse(raw) : null; } catch (e) { return null; }
};

export const clearRememberedCredentials = () => { localStorage.removeItem('rememberedCredentials'); };

// OTP simulation remains local-only
const OTP_KEY = 'passwordOtps';
const OTP_TTL_MS = 1000 * 60 * 10;
function generateOtp() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function _loadOtps() { try { return JSON.parse(localStorage.getItem(OTP_KEY) || '[]'); } catch (e) { return []; } }
function _saveOtps(arr) { localStorage.setItem(OTP_KEY, JSON.stringify(arr)); }
export const initiateForgotPassword = (email) => {
  const exists = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!exists) return { success: false, message: 'No account found for that email' };
  const otp = generateOtp(); const expiresAt = Date.now() + OTP_TTL_MS;
  const otps = _loadOtps().filter(o => o.email.toLowerCase() !== email.toLowerCase()); otps.push({ email: email.toLowerCase(), otp, expiresAt }); _saveOtps(otps);
  console.info(`Forgot-password OTP for ${email}: ${otp} (valid for ${OTP_TTL_MS/60000} mins)`);
  return { success: true, message: 'OTP generated and (simulated) sent to email (check console in dev).' };
};

export const verifyOtpAndReset = (email, otp, newPassword) => {
  const normalized = email.toLowerCase(); const otps = _loadOtps(); const recordIdx = otps.findIndex(o => o.email === normalized && o.otp === otp);
  if (recordIdx === -1) return { success: false, message: 'Invalid OTP' };
  const record = otps[recordIdx]; if (Date.now() > record.expiresAt) { otps.splice(recordIdx, 1); _saveOtps(otps); return { success: false, message: 'OTP expired' }; }
  const user = users.find(u => u.email.toLowerCase() === normalized); if (!user) return { success: false, message: 'User record not found' };
  user.password = newPassword; try { const registeredUsers = JSON.parse(localStorage.getItem('registeredUsers') || '[]'); const idx = registeredUsers.findIndex(u => u.email.toLowerCase() === normalized); if (idx !== -1) { registeredUsers[idx].password = newPassword; localStorage.setItem('registeredUsers', JSON.stringify(registeredUsers)); } } catch (e) {}
  otps.splice(recordIdx, 1); _saveOtps(otps); return { success: true, message: 'Password reset successful' };
};