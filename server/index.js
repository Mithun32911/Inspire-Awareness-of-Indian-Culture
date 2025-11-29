const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const PORT = process.env.PORT || 4000;
const DB_PATH = path.join(__dirname, 'db', 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const app = express();
app.use(cors());
app.use(express.json());

function readUsers() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (e) {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2), 'utf8');
}

app.get('/api/ping', (req, res) => res.json({ ok: true }));

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name, role } = req.body || {};
  if (!email || !password || !name || !role) return res.status(400).json({ success: false, message: 'All fields are required' });

  const users = readUsers();
  const existing = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (existing) return res.status(409).json({ success: false, message: 'User with this email already exists' });

  if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now() + '-' + Math.random().toString(36).slice(2,8),
    email: email.toLowerCase(),
    passwordHash,
    name,
    role,
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  writeUsers(users);

  const token = jwt.sign({ id: newUser.id, email: newUser.email, role: newUser.role }, JWT_SECRET, { expiresIn: '30d' });

  res.json({ success: true, user: { email: newUser.email, name: newUser.name, role: newUser.role }, token });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ success: true, user: { email: user.email, name: user.name, role: user.role }, token });
});

// Simple endpoint to list users (for dev/debug) - DO NOT enable in production
app.get('/api/auth/list', (req, res) => {
  const users = readUsers().map(u => ({ email: u.email, role: u.role, createdAt: u.createdAt }));
  res.json({ success: true, users });
});

app.listen(PORT, () => console.log(`Auth server listening on http://localhost:${PORT}`));
