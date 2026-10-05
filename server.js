require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('./db');

const isProd = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;

if (isProd && !process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET must be set in production.');
  process.exit(1);
}
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-secret-not-for-production';

const app = express();

// Hosts like Render sit behind a proxy; this lets secure cookies work
if (isProd) app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: isProd ? [] : null
    }
  }
}));

app.use(express.json({ limit: '10kb' }));

app.use(session({
  store: new SqliteStore({
    client: db,
    expired: { clear: true, intervalMs: 15 * 60 * 1000 }
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  message: { error: 'Too many attempts. Please try again later.' }
});

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not logged in.' });
  }
  next();
}

// Used by the host to check the server is alive
app.get('/healthz', (req, res) => res.send('ok'));

// ---------- SIGN UP ----------
app.post('/api/auth/register', authLimiter, (req, res) => {
  const { email, password, displayName } = req.body || {};

  if (typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email.' });
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 72) {
    return res.status(400).json({ error: 'Password must be 8 to 72 characters.' });
  }
  if (typeof displayName !== 'string' || !displayName.trim() || displayName.trim().length > 40) {
    return res.status(400).json({ error: 'Name must be 1 to 40 characters.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanName = displayName.trim();

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
  if (existing) {
    return res.status(409).json({ error: 'That email is already registered.' });
  }

  const hash = bcrypt.hashSync(password, 12);
  const info = db
    .prepare('INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?)')
    .run(cleanEmail, hash, cleanName);

  req.session.userId = info.lastInsertRowid;
  res.status(201).json({ id: info.lastInsertRowid, displayName: cleanName });
});

// ---------- LOG IN ----------
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(email.trim().toLowerCase());

  const passwordOk = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH);

  if (!user || !passwordOk) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Something went wrong.' });
    req.session.userId = user.id;
    res.json({ id: user.id, displayName: user.display_name });
  });
});

// ---------- LOG OUT ----------
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

// ---------- WHO AM I ----------
app.get('/api/me', requireAuth, (req, res) => {
  const user = db
    .prepare('SELECT id, email, display_name FROM users WHERE id = ?')
    .get(req.session.userId);
  res.json({ id: user.id, email: user.email, displayName: user.display_name });
});

// ---------- PROGRESS ----------
const VALID_CODES = new Set([
  'A01:2021', 'A02:2021', 'A03:2021', 'A04:2021', 'A05:2021',
  'A06:2021', 'A07:2021', 'A08:2021', 'A09:2021', 'A10:2021'
]);

app.get('/api/progress', requireAuth, (req, res) => {
  const rows = db
    .prepare('SELECT risk_code, completed_at FROM progress WHERE user_id = ?')
    .all(req.session.userId);
  res.json({ completed: rows.map(r => r.risk_code), details: rows });
});

app.put('/api/progress/:code', requireAuth, (req, res) => {
  const code = req.params.code;
  if (!VALID_CODES.has(code)) {
    return res.status(400).json({ error: 'Unknown risk code.' });
  }
  db.prepare('INSERT OR IGNORE INTO progress (user_id, risk_code) VALUES (?, ?)')
    .run(req.session.userId, code);
  res.json({ ok: true, code });
});

app.delete('/api/progress/:code', requireAuth, (req, res) => {
  const code = req.params.code;
  if (!VALID_CODES.has(code)) {
    return res.status(400).json({ error: 'Unknown risk code.' });
  }
  db.prepare('DELETE FROM progress WHERE user_id = ? AND risk_code = ?')
    .run(req.session.userId, code);
  res.json({ ok: true, code });
});

// ---------- QUIZ ----------
const QUIZ_TOTAL = 10;

app.post('/api/quiz/attempts', requireAuth, (req, res) => {
  const { score, total } = req.body || {};
  if (!Number.isInteger(score) || !Number.isInteger(total) ||
      total !== QUIZ_TOTAL || score < 0 || score > total) {
    return res.status(400).json({ error: 'Invalid score.' });
  }
  const info = db
    .prepare('INSERT INTO quiz_attempts (user_id, score, total) VALUES (?, ?, ?)')
    .run(req.session.userId, score, total);
  res.status(201).json({ id: info.lastInsertRowid, score, total });
});

app.get('/api/quiz/attempts', requireAuth, (req, res) => {
  const rows = db
    .prepare('SELECT id, score, total, created_at FROM quiz_attempts WHERE user_id = ? ORDER BY id DESC')
    .all(req.session.userId);
  res.json(rows);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});