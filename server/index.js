const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const PORT = process.env.PORT || 4000;
const DB_FILE = path.join(__dirname, 'db', 'auth.db');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const app = express();
app.use(cors());
app.use(express.json());

// Initialize SQLite DB and users table
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    passwordHash TEXT NOT NULL,
    name TEXT,
    role TEXT,
    createdAt TEXT
  )`);
});

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(err) { if (err) reject(err); else resolve(this); }));
}

app.get('/api/ping', (req, res) => res.json({ ok: true }));

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name, role } = req.body || {};
  if (!email || !password || !name || !role) return res.status(400).json({ success: false, message: 'All fields are required' });

  try {
    const existing = await dbGet('SELECT id FROM users WHERE lower(email)=lower(?)', [email]);
    if (existing) return res.status(409).json({ success: false, message: 'User with this email already exists' });

    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

    const passwordHash = await bcrypt.hash(password, 10);
    const id = Date.now() + '-' + Math.random().toString(36).slice(2,8);
    await dbRun('INSERT INTO users (id,email,passwordHash,name,role,createdAt) VALUES (?,?,?,?,?,?)', [id, email.toLowerCase(), passwordHash, name, role, new Date().toISOString()]);

    const token = jwt.sign({ id, email: email.toLowerCase(), role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, user: { email: email.toLowerCase(), name, role }, token });
  } catch (e) {
    console.error('Register error', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });

  try {
    const user = await dbGet('SELECT * FROM users WHERE lower(email)=lower(?)', [email]);
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, user: { email: user.email, name: user.name, role: user.role }, token });
  } catch (e) {
    console.error('Login error', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Protected middleware example
function verifyToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer (.+)$/i);
  if (!m) return res.status(401).json({ success: false, message: 'Missing token' });
  const token = m[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

// Developer-only list endpoint (protected by token for mild safety)
app.get('/api/auth/list', verifyToken, async (req, res) => {
  try {
    const rows = await dbAll('SELECT email, role, createdAt FROM users');
    res.json({ success: true, users: rows });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.listen(PORT, () => console.log(`Auth server listening on http://localhost:${PORT}`));
