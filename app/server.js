'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { extractZip, ZipError } = require('./lib/ziputil');
const { encryptVars, decryptVars, validateVars } = require('./lib/secrets');
const { createRunner } = require('./lib/runner');

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET === 'PASTE_YOUR_SECRET_HERE') {
  throw new Error('Set a real SESSION_SECRET in the environment.');
}

const PORT = process.env.PORT || 3000;
const MAX_BOTS_PER_USER = 2;
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_SETUP_CODE = process.env.ADMIN_SETUP_CODE || '';

const app = express();
const dataDir = path.join(__dirname, 'data');
const botsRoot = path.join(dataDir, 'bots');
fs.mkdirSync(botsRoot, { recursive: true });

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '32kb' }));

// ---------- database ----------
const db = new Database(path.join(dataDir, 'panel.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT 'zip',
    status TEXT NOT NULL DEFAULT 'installing',
    entry TEXT,
    env_blob TEXT,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    last_exit TEXT,
    last_started_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Older databases may have the first version of the bots table. Add any
// missing columns (SQLite cannot add columns with non-constant defaults).
function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some(c => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}
ensureColumn('users', 'disabled', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('bots', 'entry', 'TEXT');
ensureColumn('bots', 'env_blob', 'TEXT');
ensureColumn('bots', 'size_bytes', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('bots', 'last_exit', 'TEXT');
ensureColumn('bots', 'last_started_at', 'TEXT');
ensureColumn('bots', 'updated_at', 'TEXT');

const runner = createRunner({
  db,
  botsRoot,
  loadEnv: bot => decryptVars(bot.env_blob)
});
runner.recover();

// ---------- sessions ----------
app.use(session({
  name: 'legendary.sid',
  secret: process.env.SESSION_SECRET,
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: dataDir,
    table: 'sessions'
  }),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: 'auto',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 12
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many attempts. Please try again in 15 minutes.' }
});

// ---------- statements ----------
const findUser = db.prepare(`
  SELECT id, username, email, password_hash, role, disabled
  FROM users WHERE email = ? OR username = ?
`);
const getUserById = db.prepare(
  'SELECT id, username, email, role, disabled FROM users WHERE id = ?'
);
const setRole = db.prepare('UPDATE users SET role = ? WHERE id = ?');
const setDisabled = db.prepare('UPDATE users SET disabled = ? WHERE id = ?');
const countUserBots = db.prepare('SELECT COUNT(*) AS n FROM bots WHERE user_id = ?');
const listUserBots = db.prepare('SELECT * FROM bots WHERE user_id = ? ORDER BY id DESC');
const getUserBot = db.prepare('SELECT * FROM bots WHERE id = ? AND user_id = ?');
const getBotById = db.prepare('SELECT * FROM bots WHERE id = ?');
const insertBot = db.prepare(`
  INSERT INTO bots (user_id, name, source_type, status, updated_at)
  VALUES (?, ?, 'zip', 'installing', datetime('now'))
`);
const deleteBot = db.prepare('DELETE FROM bots WHERE id = ?');
const setBotEnv = db.prepare(
  "UPDATE bots SET env_blob = ?, updated_at = datetime('now') WHERE id = ?"
);
const setBotEntry = db.prepare(
  "UPDATE bots SET entry = ?, updated_at = datetime('now') WHERE id = ?"
);

// ---------- helpers ----------
function publicUser(user) {
  return { id: user.id, username: user.username, email: user.email, role: user.role };
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

function publicBot(bot) {
  const usage = runner.usage(bot.id);
  return {
    id: bot.id,
    name: bot.name,
    status: bot.status,
    entry: bot.entry,
    sizeBytes: bot.size_bytes || 0,
    lastExit: bot.last_exit,
    lastStartedAt: bot.last_started_at,
    createdAt: bot.created_at,
    updatedAt: bot.updated_at,
    running: runner.isRunning(bot.id),
    memoryMb: usage ? usage.memoryMb : null,
    uptimeSec: usage ? usage.uptimeSec : null,
    envNames: Object.keys(decryptVars(bot.env_blob))
  };
}

function botDir(id) {
  return path.join(botsRoot, String(id));
}

function removeBotFiles(id) {
  fs.rmSync(botDir(id), { recursive: true, force: true });
}

// GitHub-style ZIPs wrap everything in one folder. Lift that folder's contents up.
function unwrapSingleFolder(code) {
  const items = fs.readdirSync(code);
  if (items.length !== 1) return;
  const inner = path.join(code, items[0]);
  if (!fs.statSync(inner).isDirectory()) return;
  const tmp = code + '-unwrap';
  fs.renameSync(code, tmp);
  fs.renameSync(path.join(tmp, items[0]), code);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// Works out which file starts the bot. Returns a path relative to the code folder.
function detectEntry(code) {
  let pkg = null;
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(code, 'package.json'), 'utf8'));
  } catch (_) {}

  const candidates = [];
  if (pkg && typeof pkg.main === 'string') candidates.push(pkg.main);
  const start = pkg && pkg.scripts && pkg.scripts.start;
  if (typeof start === 'string') {
    const m = /^node\s+([^\s&|;<>]+\.js)$/.exec(start.trim());
    if (m) candidates.push(m[1]);
  }
  candidates.push('index.js', 'bot.js', 'main.js', 'app.js');

  for (const c of candidates) {
    if (typeof c !== 'string' || c.includes('..')) continue;
    const abs = path.resolve(code, c);
    if (!abs.startsWith(code + path.sep)) continue;
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
      return path.relative(code, abs);
    }
  }
  return null;
}

// ---------- auth ----------
function requireLogin(req, res, next) {
  const sess = req.session && req.session.user;
  const deny = () => res.status(401).json({ success: false, error: 'Please log in first.' });
  if (!sess) return deny();

  const row = getUserById.get(sess.id);
  if (!row || row.disabled) {
    return req.session.destroy(() => deny());
  }
  req.user = publicUser(row);
  req.session.user = req.user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admins only.' });
  }
  next();
}

function startUserSession(req, user, res, status) {
  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Could not create session.' });
    }
    req.session.user = publicUser(user);
    req.session.save((saveErr) => {
      if (saveErr) {
        return res.status(500).json({ success: false, error: 'Could not save session.' });
      }
      res.status(status).json({
        success: true,
        message: status === 201 ? 'Account created successfully.' : 'Login successful.',
        user: req.session.user
      });
    });
  });
}

// ---------- public routes ----------
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    panel: 'LEGENDARY FREE PANEL',
    status: 'online',
    sandbox: runner.sandboxAvailable,
    limits: { maxBotsPerUser: MAX_BOTS_PER_USER, ...runner.limits }
  });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (typeof username !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ success: false, error: 'Username, email and password are required.' });
    }

    const cleanUsername = username.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(cleanUsername)) {
      return res.status(400).json({
        success: false,
        error: 'Username must be 3–24 characters using letters, numbers or underscores.'
      });
    }
    if (cleanEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ success: false, error: 'Enter a valid email address.' });
    }
    if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 12 characters and no more than 72 bytes.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    let result;
    try {
      result = db.prepare(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
      ).run(cleanUsername, cleanEmail, passwordHash);
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({
          success: false,
          error: 'That username or email is already registered.'
        });
      }
      throw err;
    }

    const user = {
      id: Number(result.lastInsertRowid),
      username: cleanUsername,
      email: cleanEmail,
      role: 'user',
      disabled: 0
    };
    startUserSession(req, user, res, 201);
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({ success: false, error: 'Could not complete registration.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (
      typeof identifier !== 'string' ||
      typeof password !== 'string' ||
      identifier.length > 254 ||
      password.length > 72
    ) {
      return res.status(400).json({
        success: false,
        error: 'Enter your username or email and password.'
      });
    }

    const value = identifier.trim();
    const user = findUser.get(value.toLowerCase(), value);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username/email or password.'
      });
    }
    if (user.disabled) {
      return res.status(403).json({ success: false, error: 'This account has been disabled.' });
    }

    startUserSession(req, user, res, 200);
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, error: 'Could not complete login.' });
  }
});

app.get('/api/me', requireLogin, (req, res) => {
  res.json({ success: true, user: req.user });
});

app.post('/api/auth/logout', requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Could not log out.' });
    }
    res.clearCookie('legendary.sid', { httpOnly: true, secure: 'auto', sameSite: 'lax' });
    res.json({ success: true, message: 'Logged out successfully.' });
  });
});

// Promotes the logged-in account to admin. Needs the admin email AND the
// secret setup code, so a stranger who registers the admin email cannot
// take over the panel.
app.post('/api/admin/claim', authLimiter, requireLogin, (req, res) => {
  if (!ADMIN_EMAIL || !ADMIN_SETUP_CODE) {
    return res.status(404).json({ success: false, error: 'Not available.' });
  }
  const code = req.body && typeof req.body.code === 'string' ? req.body.code : '';
  if (req.user.email !== ADMIN_EMAIL || !safeEqual(code, ADMIN_SETUP_CODE)) {
    return res.status(403).json({ success: false, error: 'Not allowed.' });
  }
  setRole.run('admin', req.user.id);
  req.user.role = 'admin';
  req.session.user = req.user;
  res.json({ success: true, message: 'Admin access granted.', user: req.user });
});

// ---------- bots (owner only) ----------
app.get('/api/bots', requireLogin, (req, res) => {
  const bots = listUserBots.all(req.user.id).map(publicBot);
  res.json({ success: true, bots, limit: MAX_BOTS_PER_USER });
});

app.post(
  '/api/bots',
  requireLogin,
  express.raw({
    type: ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'],
    limit: MAX_UPLOAD_BYTES
  }),
  (req, res) => {
    const name = typeof req.query.name === 'string' ? req.query.name.trim() : '';
    if (!/^[\w .-]{1,40}$/.test(name)) {
      return res.status(400).json({
        success: false,
        error: 'Give your bot a name (1–40 letters, numbers, spaces, dashes or underscores).'
      });
    }
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ success: false, error: 'Upload a ZIP file.' });
    }
    if (!runner.sandboxAvailable) {
      return res.status(503).json({
        success: false,
        error: 'This server cannot run bots safely yet, so uploads are paused.'
      });
    }
    if (countUserBots.get(req.user.id).n >= MAX_BOTS_PER_USER) {
      return res.status(409).json({
        success: false,
        error: 'You can have at most ' + MAX_BOTS_PER_USER + ' bots. Delete one first.'
      });
    }

    const id = Number(insertBot.run(req.user.id, name).lastInsertRowid);
    const code = path.join(botDir(id), 'code');
    const cleanup = () => {
      removeBotFiles(id);
      deleteBot.run(id);
    };

    try {
      extractZip(req.body, code);
      unwrapSingleFolder(code);
    } catch (err) {
      cleanup();
      if (err instanceof ZipError) {
        return res.status(400).json({ success: false, error: err.message });
      }
      console.error('Upload error:', err.message);
      return res.status(500).json({ success: false, error: 'Could not read that ZIP file.' });
    }

    const entry = detectEntry(code);
    if (!entry) {
      cleanup();
      return res.status(400).json({
        success: false,
        error: 'No runnable Node.js file found. Include a package.json with "main" or ' +
          '"scripts.start" (for example "node index.js"), or an index.js file.'
      });
    }

    setBotEntry.run(entry, id);
    runner.install(id);
    res.status(202).json({
      success: true,
      message: 'Upload received. Installing dependencies…',
      bot: publicBot(getBotById.get(id))
    });
  }
);

app.get('/api/bots/:id', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  res.json({ success: true, bot: publicBot(bot) });
});

app.get('/api/bots/:id/logs', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  res.json({ success: true, logs: runner.tail(bot.id, 300) });
});

app.post('/api/bots/:id/start', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  if (bot.status === 'installing') {
    return res.status(409).json({ success: false, error: 'Still installing. Try again in a moment.' });
  }
  if (bot.status === 'install_failed') {
    return res.status(409).json({
      success: false,
      error: 'Install failed. Check the logs, then delete and upload again.'
    });
  }
  const result = runner.start(bot);
  if (!result.ok) return res.status(409).json({ success: false, error: result.error });
  res.json({ success: true, message: 'Bot starting.', bot: publicBot(getBotById.get(bot.id)) });
});

app.post('/api/bots/:id/stop', requireLogin, async (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  await runner.stop(bot.id);
  res.json({ success: true, message: 'Bot stopped.', bot: publicBot(getBotById.get(bot.id)) });
});

app.post('/api/bots/:id/restart', requireLogin, async (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  if (bot.status === 'installing' || bot.status === 'install_failed') {
    return res.status(409).json({ success: false, error: 'Bot is not ready to run.' });
  }
  const result = await runner.restart(getBotById.get(bot.id));
  if (!result.ok) return res.status(409).json({ success: false, error: result.error });
  res.json({ success: true, message: 'Bot restarting.', bot: publicBot(getBotById.get(bot.id)) });
});

app.delete('/api/bots/:id', requireLogin, async (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  await runner.stop(bot.id);
  runner.cancelInstall(bot.id);
  removeBotFiles(bot.id);
  deleteBot.run(bot.id);
  res.json({ success: true, message: 'Bot deleted.' });
});

// Environment variables: names are shown, values are never sent back.
app.get('/api/bots/:id/env', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  res.json({ success: true, names: Object.keys(decryptVars(bot.env_blob)) });
});

app.put('/api/bots/:id/env', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });

  const checked = validateVars(req.body && req.body.vars);
  if (checked.error) return res.status(400).json({ success: false, error: checked.error });

  setBotEnv.run(encryptVars(checked.vars), bot.id);
  res.json({
    success: true,
    message: runner.isRunning(bot.id)
      ? 'Saved. Restart the bot to use the new values.'
      : 'Saved. They will be used the next time you start the bot.',
    names: Object.keys(checked.vars)
  });
});

// ---------- admin ----------
app.get('/api/admin/overview', requireLogin, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  const bots = db.prepare('SELECT COUNT(*) AS n FROM bots').get().n;
  res.json({
    success: true,
    users,
    bots,
    running: runner.runningCount(),
    sandbox: runner.sandboxAvailable,
    limits: { maxBotsPerUser: MAX_BOTS_PER_USER, ...runner.limits }
  });
});

app.get('/api/admin/users', requireLogin, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.email, u.role, u.disabled, u.created_at,
           (SELECT COUNT(*) FROM bots b WHERE b.user_id = u.id) AS bot_count
    FROM users u ORDER BY u.id DESC
  `).all();
  res.json({
    success: true,
    users: rows.map(r => ({ ...r, disabled: !!r.disabled }))
  });
});

app.post('/api/admin/users/:id/disable', requireLogin, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) {
    return res.status(400).json({ success: false, error: 'You cannot disable your own account.' });
  }
  const target = getUserById.get(id);
  if (!target) return res.status(404).json({ success: false, error: 'User not found.' });

  setDisabled.run(1, id);
  const bots = listUserBots.all(id);
  for (const bot of bots) {
    await runner.stop(bot.id);
  }
  res.json({ success: true, message: 'Account disabled and its bots stopped.' });
});

app.post('/api/admin/users/:id/enable', requireLogin, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = getUserById.get(id);
  if (!target) return res.status(404).json({ success: false, error: 'User not found.' });
  setDisabled.run(0, id);
  res.json({ success: true, message: 'Account enabled.' });
});

app.get('/api/admin/bots', requireLogin, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT b.*, u.username AS owner
    FROM bots b JOIN users u ON u.id = b.user_id
    ORDER BY b.id DESC
  `).all();
  res.json({
    success: true,
    bots: rows.map(b => ({
      id: b.id,
      owner: b.owner,
      name: b.name,
      status: b.status,
      sizeBytes: b.size_bytes || 0,
      lastExit: b.last_exit,
      running: runner.isRunning(b.id)
    }))
  });
});

app.post('/api/admin/bots/:id/stop', requireLogin, requireAdmin, async (req, res) => {
  const bot = getBotById.get(Number(req.params.id));
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  await runner.stop(bot.id);
  res.json({ success: true, message: 'Bot stopped.' });
});

// ---------- errors ----------
app.use('/api', (req, res) => {
  res.status(404).json({ success: false, error: 'Not found.' });
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'File is too large. The limit is 25 MB.' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'The request is not valid JSON.' });
  }
  console.error('Unhandled error:', err.message);
  res.status(500).json({ success: false, error: 'Something went wrong.' });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`LEGENDARY FREE PANEL backend listening on port ${PORT}`);
  if (!runner.sandboxAvailable) {
    console.log('WARNING: Node permission model unavailable; bot uploads are disabled.');
  }
});

function shutdown() {
  runner.shutdownAll();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
