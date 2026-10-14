'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
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
app.use(express.json({ limit: '600kb' }));

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
ensureColumn('bots', 'source_ref', 'TEXT');
ensureColumn('users', 'github_login', 'TEXT');
ensureColumn('users', 'github_token_blob', 'TEXT');

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
  INSERT INTO bots (user_id, name, source_type, source_ref, status, updated_at)
  VALUES (?, ?, ?, ?, 'installing', datetime('now'))
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
    sourceType: bot.source_type,
    sourceRef: bot.source_ref || null,
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

// ---------- creating bots (shared by ZIP upload and GitHub import) ----------
class UserError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status || 400;
  }
}

const NO_ENTRY_MESSAGE = 'No runnable Node.js file found. Include a package.json with "main" or ' +
  '"scripts.start" (for example "node index.js"), or an index.js file.';

// Works out the file to run from the "Command run" field. Only "npm start" and
// "node yourfile.js" are accepted. Arbitrary shell commands are refused because
// they would get around the bot sandbox.
function resolveEntry(code, startCommand) {
  const cmd = String(startCommand || '').trim();
  if (!cmd || /^npm\s+start$/i.test(cmd)) {
    const found = detectEntry(code);
    return found ? { entry: found } : { error: NO_ENTRY_MESSAGE };
  }
  const m = /^node\s+([\w./-]{1,200}\.(?:js|mjs|cjs))$/.exec(cmd);
  if (!m) {
    return { error: 'Command run must be "npm start" or "node yourfile.js".' };
  }
  const abs = path.resolve(code, m[1]);
  if (!abs.startsWith(code + path.sep) || !fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    return { error: 'That file was not found in the repo: ' + m[1] };
  }
  return { entry: path.relative(code, abs) };
}

function hasSymlinks(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.isSymbolicLink()) return true;
    if (ent.isDirectory() && hasSymlinks(path.join(dir, ent.name))) return true;
  }
  return false;
}

// Clones a public or private GitHub repo with git. The token is passed through
// environment variables (not the command line) and is never written to disk or logs.
function gitClone({ url, branch, username, token, dest, home }) {
  return new Promise((resolve, reject) => {
    const env = {
      PATH: process.env.PATH,
      HOME: home,
      GIT_TERMINAL_PROMPT: '0',
      GIT_CONFIG_NOSYSTEM: '1'
    };
    if (token) {
      const basic = Buffer.from((username || 'x-access-token') + ':' + token).toString('base64');
      env.GIT_CONFIG_COUNT = '2';
      env.GIT_CONFIG_KEY_0 = 'credential.helper';
      env.GIT_CONFIG_VALUE_0 = '';
      env.GIT_CONFIG_KEY_1 = 'http.extraHeader';
      env.GIT_CONFIG_VALUE_1 = 'Authorization: Basic ' + basic;
    }

    const args = ['clone', '--depth', '1', '--single-branch', '--no-tags', '--quiet'];
    if (branch) args.push('--branch', branch);
    args.push(url, dest);

    fs.mkdirSync(home, { recursive: true });
    let child;
    try {
      child = spawn('git', args, { cwd: home, env, stdio: ['ignore', 'ignore', 'pipe'] });
    } catch (err) {
      return reject(new UserError('Git is not available on this server.', 503));
    }

    let errText = '';
    child.stderr.on('data', (d) => { if (errText.length < 2000) errText += d.toString(); });
    const timer = setTimeout(() => child.kill('SIGKILL'), 90000);
    child.on('error', () => {
      clearTimeout(timer);
      reject(new UserError('Git is not available on this server.', 503));
    });
    child.on('exit', (exitCode) => {
      clearTimeout(timer);
      if (exitCode === 0) return resolve();
      console.error('git clone failed:', errText.slice(0, 300));
      reject(new UserError(
        'Could not download the repo. Check the address and branch, and add a token if the repo is private.',
        502
      ));
    });
  });
}

// Creates a bot record, fills its code folder, works out the entry file and
// starts the install. fill(code) puts the code in place (ZIP or git clone).
async function createBot({ userId, name, source, sourceRef, startCommand, fill }) {
  if (!/^[\w .-]{1,40}$/.test(name)) {
    return { status: 400, body: { success: false, error: 'Give your bot a name (1–40 letters, numbers, spaces, dashes or underscores).' } };
  }
  if (!runner.sandboxAvailable) {
    return { status: 503, body: { success: false, error: 'This server cannot run bots safely yet, so new bots are paused.' } };
  }
  if (countUserBots.get(userId).n >= MAX_BOTS_PER_USER) {
    return { status: 409, body: { success: false, error: 'You can have at most ' + MAX_BOTS_PER_USER + ' bots. Delete one first.' } };
  }

  const id = Number(insertBot.run(userId, name, source, sourceRef || null).lastInsertRowid);
  const code = path.join(botDir(id), 'code');
  const cleanup = () => {
    removeBotFiles(id);
    deleteBot.run(id);
  };

  try {
    await fill(code);
  } catch (err) {
    cleanup();
    if (err instanceof UserError) return { status: err.status, body: { success: false, error: err.message } };
    if (err instanceof ZipError) return { status: 400, body: { success: false, error: err.message } };
    console.error('Bot import error:', err.message);
    return { status: 500, body: { success: false, error: 'Could not import that code.' } };
  }

  const resolved = resolveEntry(code, startCommand);
  if (resolved.error) {
    cleanup();
    return { status: 400, body: { success: false, error: resolved.error } };
  }

  setBotEntry.run(resolved.entry, id);
  runner.install(id);
  return {
    status: 202,
    body: { success: true, message: 'Installing dependencies…', bot: publicBot(getBotById.get(id)) }
  };
}

// ---------- ZIP upload ----------
app.post(
  '/api/bots',
  requireLogin,
  express.raw({
    type: ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'],
    limit: MAX_UPLOAD_BYTES
  }),
  async (req, res) => {
    const name = typeof req.query.name === 'string' ? req.query.name.trim() : '';
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ success: false, error: 'Upload a ZIP file.' });
    }
    const zip = req.body;
    const out = await createBot({
      userId: req.user.id,
      name,
      source: 'zip',
      fill: (code) => {
        extractZip(zip, code);
        unwrapSingleFolder(code);
      }
    });
    res.status(out.status).json(out.body);
  }
);

// ---------- GitHub ----------
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');

const getGithub = db.prepare('SELECT github_login, github_token_blob FROM users WHERE id = ?');
const setGithub = db.prepare('UPDATE users SET github_login = ?, github_token_blob = ? WHERE id = ?');

function githubConfigured() {
  return !!(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET && PUBLIC_URL);
}

function githubToken(userId) {
  const row = getGithub.get(userId);
  if (!row || !row.github_token_blob) return null;
  const token = decryptVars(row.github_token_blob).token;
  return typeof token === 'string' && token ? token : null;
}

function githubFetch(url, token, accept) {
  return fetch(url, {
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: accept || 'application/vnd.github+json',
      'User-Agent': 'legendary-free-panel',
      'X-GitHub-Api-Version': '2022-11-28'
    },
    redirect: 'follow'
  });
}

app.get('/api/github/status', requireLogin, (req, res) => {
  const row = getGithub.get(req.user.id);
  res.json({
    success: true,
    configured: githubConfigured(),
    connected: !!(row && row.github_token_blob),
    login: row ? row.github_login : null
  });
});

// Starts the GitHub sign-in. The browser is sent to GitHub and comes back to /callback.
app.get('/api/github/connect', requireLogin, (req, res) => {
  if (!githubConfigured()) {
    return res.status(503).send('GitHub sign-in is not set up on this server yet.');
  }
  const state = crypto.randomBytes(24).toString('hex');
  req.session.githubState = state;
  req.session.save((err) => {
    if (err) return res.status(500).send('Could not start GitHub sign-in.');
    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      redirect_uri: PUBLIC_URL + '/api/github/callback',
      scope: 'repo read:user',
      state,
      allow_signup: 'false'
    });
    res.redirect('https://github.com/login/oauth/authorize?' + params.toString());
  });
});

app.get('/api/github/callback', requireLogin, async (req, res) => {
  const back = (result) => res.redirect('/?github=' + result);
  try {
    const { code, state } = req.query;
    const expected = req.session.githubState;
    delete req.session.githubState;

    if (!expected || typeof state !== 'string' || !safeEqual(state, expected) ||
        typeof code !== 'string' || code.length > 200) {
      return back('denied');
    }
    if (!githubConfigured()) return back('notset');

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: PUBLIC_URL + '/api/github/callback'
      })
    });
    const tokenData = await tokenRes.json().catch(() => ({}));
    if (!tokenData.access_token) return back('failed');

    const userRes = await githubFetch('https://api.github.com/user', tokenData.access_token);
    if (!userRes.ok) return back('failed');
    const gh = await userRes.json();

    setGithub.run(
      String(gh.login).slice(0, 39),
      encryptVars({ token: tokenData.access_token }),
      req.user.id
    );
    back('connected');
  } catch (err) {
    console.error('GitHub callback error:', err.message);
    back('failed');
  }
});

app.post('/api/github/disconnect', requireLogin, (req, res) => {
  setGithub.run(null, null, req.user.id);
  res.json({ success: true, message: 'GitHub disconnected.' });
});

app.get('/api/github/repos', requireLogin, async (req, res) => {
  const token = githubToken(req.user.id);
  if (!token) {
    return res.status(409).json({ success: false, error: 'Connect your GitHub account first.' });
  }
  try {
    const r = await githubFetch(
      'https://api.github.com/user/repos?sort=pushed&per_page=100&affiliation=owner,collaborator,organization_member',
      token
    );
    if (r.status === 401) {
      return res.status(401).json({ success: false, error: 'GitHub access has expired. Connect again.' });
    }
    if (!r.ok) {
      return res.status(502).json({ success: false, error: 'GitHub did not return your repositories.' });
    }
    const list = await r.json();
    res.json({
      success: true,
      repos: list.map(x => ({
        fullName: x.full_name,
        private: !!x.private,
        defaultBranch: x.default_branch,
        description: x.description || ''
      }))
    });
  } catch (err) {
    console.error('GitHub repos error:', err.message);
    res.status(502).json({ success: false, error: 'Could not reach GitHub.' });
  }
});

app.post('/api/bots/from-github', requireLogin, async (req, res) => {
  const repo = req.body && typeof req.body.repo === 'string' ? req.body.repo.trim() : '';
  const branch = req.body && typeof req.body.branch === 'string' ? req.body.branch.trim() : '';

  if (!/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repo)) {
    return res.status(400).json({ success: false, error: 'Choose a repository.' });
  }
  if (branch && (!/^[\w./-]{1,200}$/.test(branch) || branch.includes('..'))) {
    return res.status(400).json({ success: false, error: 'That branch name is not valid.' });
  }

  const token = githubToken(req.user.id);
  if (!token) {
    return res.status(409).json({ success: false, error: 'Connect your GitHub account first.' });
  }
  if (!runner.sandboxAvailable) {
    return res.status(503).json({ success: false, error: 'This server cannot run bots safely yet, so new bots are paused.' });
  }
  if (countUserBots.get(req.user.id).n >= MAX_BOTS_PER_USER) {
    return res.status(409).json({
      success: false,
      error: 'You can have at most ' + MAX_BOTS_PER_USER + ' bots. Delete one first.'
    });
  }

  let zip;
  try {
    const ref = branch ? '/' + encodeURIComponent(branch) : '';
    const r = await githubFetch('https://api.github.com/repos/' + repo + '/zipball' + ref, token, 'application/vnd.github+json');
    if (r.status === 401) {
      return res.status(401).json({ success: false, error: 'GitHub access has expired. Connect again.' });
    }
    if (r.status === 404) {
      return res.status(404).json({ success: false, error: 'That repository or branch was not found, or your GitHub account cannot access it.' });
    }
    if (!r.ok) {
      return res.status(502).json({ success: false, error: 'GitHub did not return the code. Try again.' });
    }
    const declared = Number(r.headers.get('content-length') || 0);
    if (declared > MAX_UPLOAD_BYTES) {
      return res.status(413).json({ success: false, error: 'This repository is larger than 25 MB.' });
    }
    zip = Buffer.from(await r.arrayBuffer());
    if (zip.length > MAX_UPLOAD_BYTES) {
      return res.status(413).json({ success: false, error: 'This repository is larger than 25 MB.' });
    }
  } catch (err) {
    console.error('GitHub download error:', err.message);
    return res.status(502).json({ success: false, error: 'Could not download the code from GitHub.' });
  }

  const name = repo.split('/')[1].slice(0, 40);
  const out = await createBot({
    userId: req.user.id,
    name,
    source: 'github',
    sourceRef: repo + (branch ? '@' + branch : ''),
    fill: (code) => {
      extractZip(zip, code);
      unwrapSingleFolder(code);
    }
  });
  res.status(out.status).json(out.body);
});

// Deploy from a GitHub address you paste (public or private repo).
app.post('/api/bots/from-git', requireLogin, async (req, res) => {
  const body = req.body || {};
  const text = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
  const address = text(body.url, 200);
  const branch = text(body.branch, 200);
  const username = text(body.username, 100);
  const token = text(body.token, 255);
  const startCommand = text(body.startCommand, 200);

  const m = /^https:\/\/github\.com\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})(?:\.git)?\/?$/.exec(address);
  if (!m) {
    return res.status(400).json({
      success: false,
      error: 'Paste a GitHub repo address, like https://github.com/owner/repo'
    });
  }
  if (branch && (!/^[\w./-]{1,200}$/.test(branch) || branch.includes('..'))) {
    return res.status(400).json({ success: false, error: 'That branch name is not valid.' });
  }
  if (username && !/^[A-Za-z0-9_.-]{1,100}$/.test(username)) {
    return res.status(400).json({ success: false, error: 'That git username is not valid.' });
  }
  if (/\s/.test(token)) {
    return res.status(400).json({ success: false, error: 'That git token is not valid.' });
  }

  const repoName = m[2].replace(/\.git$/i, '');
  const name = text(body.name, 40) || repoName.slice(0, 40);
  const cloneUrl = 'https://github.com/' + m[1] + '/' + repoName + '.git';

  const out = await createBot({
    userId: req.user.id,
    name,
    source: 'git',
    sourceRef: m[1] + '/' + repoName + (branch ? '@' + branch : ''),
    startCommand,
    fill: async (code) => {
      await gitClone({
        url: cloneUrl,
        branch,
        username,
        token,
        dest: code,
        home: path.dirname(code)
      });
      fs.rmSync(path.join(code, '.git'), { recursive: true, force: true });
      if (hasSymlinks(code)) {
        throw new UserError('The repo contains symbolic links, which are not allowed.');
      }
    }
  });
  res.status(out.status).json(out.body);
});

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

// ---------- bot files (owner only, text files only) ----------
const FILE_MAX_BYTES = 512 * 1024;
const FILES_MAX_ENTRIES = 500;

// Checks a relative path from the user and returns the absolute path inside the
// bot's code folder. Returns null for anything unsafe (absolute paths, "..",
// backslashes, symbolic links, node_modules).
function safeCodePath(codeRoot, rel) {
  if (typeof rel !== 'string' || rel.length === 0 || rel.length > 300) return null;
  if (rel.includes('\0') || rel.includes('\\') || path.isAbsolute(rel) || /^[a-zA-Z]:/.test(rel)) return null;
  const parts = rel.split('/').filter(p => p !== '' && p !== '.');
  if (parts.length === 0 || parts.length > 20) return null;
  if (parts.some(p => p === '..' || p.length > 120)) return null;
  if (parts[0] === 'node_modules') return null;

  const abs = path.resolve(codeRoot, ...parts);
  if (!abs.startsWith(codeRoot + path.sep)) return null;

  let cur = codeRoot;
  for (const p of parts) {
    cur = path.join(cur, p);
    let st;
    try { st = fs.lstatSync(cur); } catch (_) { break; }
    if (st.isSymbolicLink()) return null;
  }
  return { abs, rel: parts.join('/') };
}

function listCodeFiles(codeRoot) {
  const out = [];
  let truncated = false;
  (function walk(dir, relDir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      if (out.length >= FILES_MAX_ENTRIES) { truncated = true; return; }
      if (ent.isSymbolicLink()) continue;
      const rel = relDir ? relDir + '/' + ent.name : ent.name;
      if (ent.isDirectory()) {
        out.push({ path: rel, type: 'dir' });
        if (ent.name !== 'node_modules') walk(path.join(dir, ent.name), rel);
      } else if (ent.isFile()) {
        out.push({ path: rel, type: 'file', size: fs.statSync(path.join(dir, ent.name)).size });
      }
    }
  })(codeRoot, '');
  return { files: out, truncated };
}

app.get('/api/bots/:id/files', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  const code = path.join(botDir(bot.id), 'code');
  if (!fs.existsSync(code)) return res.json({ success: true, files: [], truncated: false });
  const listed = listCodeFiles(code);
  res.json({ success: true, files: listed.files, truncated: listed.truncated });
});

app.get('/api/bots/:id/file', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  const code = path.join(botDir(bot.id), 'code');
  const f = safeCodePath(code, req.query.path);
  if (!f) return res.status(400).json({ success: false, error: 'That file path is not valid.' });

  let st;
  try { st = fs.statSync(f.abs); } catch (_) {
    return res.status(404).json({ success: false, error: 'File not found.' });
  }
  if (!st.isFile()) return res.status(400).json({ success: false, error: 'That is a folder, not a file.' });
  if (st.size > FILE_MAX_BYTES) {
    return res.status(413).json({ success: false, error: 'This file is too large to edit here (limit 512 KB).' });
  }
  const buf = fs.readFileSync(f.abs);
  if (buf.includes(0)) {
    return res.status(415).json({ success: false, error: 'This is not a text file, so it cannot be edited here.' });
  }
  res.json({ success: true, path: f.rel, content: buf.toString('utf8') });
});

// Creates or overwrites a text file.
app.put('/api/bots/:id/file', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  if (bot.status === 'installing') {
    return res.status(409).json({ success: false, error: 'Still installing. Try again in a moment.' });
  }
  const body = req.body || {};
  if (typeof body.content !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing file content.' });
  }
  if (Buffer.byteLength(body.content, 'utf8') > FILE_MAX_BYTES) {
    return res.status(413).json({ success: false, error: 'This file is larger than 512 KB.' });
  }
  if (body.content.includes('\0')) {
    return res.status(400).json({ success: false, error: 'Only text can be saved here.' });
  }

  const code = path.join(botDir(bot.id), 'code');
  fs.mkdirSync(code, { recursive: true });
  const f = safeCodePath(code, body.path);
  if (!f) return res.status(400).json({ success: false, error: 'That file path is not valid.' });

  const existed = fs.existsSync(f.abs);
  if (!existed && listCodeFiles(code).files.length >= FILES_MAX_ENTRIES) {
    return res.status(409).json({ success: false, error: 'This bot already has the maximum number of files.' });
  }
  try {
    fs.mkdirSync(path.dirname(f.abs), { recursive: true });
    if (existed && fs.statSync(f.abs).isDirectory()) {
      return res.status(400).json({ success: false, error: 'A folder already has that name.' });
    }
    fs.writeFileSync(f.abs, body.content, { encoding: 'utf8', mode: 0o644 });
  } catch (err) {
    console.error('Save file error:', err.message);
    return res.status(500).json({ success: false, error: 'Could not save the file.' });
  }
  res.json({
    success: true,
    path: f.rel,
    message: existed ? 'Saved. Restart the bot to run the changes.' : 'File created.'
  });
});

app.delete('/api/bots/:id/file', requireLogin, (req, res) => {
  const bot = getUserBot.get(Number(req.params.id), req.user.id);
  if (!bot) return res.status(404).json({ success: false, error: 'Bot not found.' });
  const code = path.join(botDir(bot.id), 'code');
  const f = safeCodePath(code, req.query.path);
  if (!f) return res.status(400).json({ success: false, error: 'That file path is not valid.' });
  if (f.rel === bot.entry) {
    return res.status(400).json({ success: false, error: 'This is the file that starts your bot, so it cannot be deleted here.' });
  }
  let st;
  try { st = fs.statSync(f.abs); } catch (_) {
    return res.status(404).json({ success: false, error: 'File not found.' });
  }
  if (!st.isFile()) return res.status(400).json({ success: false, error: 'Only files can be deleted here.' });
  try {
    fs.unlinkSync(f.abs);
  } catch (err) {
    console.error('Delete file error:', err.message);
    return res.status(500).json({ success: false, error: 'Could not delete the file.' });
  }
  res.json({ success: true, message: 'File deleted.' });
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
