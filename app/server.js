const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET === 'PASTE_YOUR_SECRET_HERE') {
  throw new Error('Set a real SESSION_SECRET in backend/.env');
}

const app = express();
const PORT = process.env.PORT || 3000;
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '32kb' }));

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
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('zip', 'github')),
    status TEXT NOT NULL DEFAULT 'stopped',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

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
  message: {
    success: false,
    error: 'Too many attempts. Please try again in 15 minutes.'
  }
});

const findUser = db.prepare(`
  SELECT id, username, email, password_hash, role
  FROM users WHERE email = ? OR username = ?
`);

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role
  };
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      error: 'Please log in first.'
    });
  }
  next();
}

function startUserSession(req, user, res) {
  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: 'Could not create session.'
      });
    }

    req.session.user = publicUser(user);

    req.session.save((saveErr) => {
      if (saveErr) {
        return res.status(500).json({
          success: false,
          error: 'Could not save session.'
        });
      }

      res.json({
        success: true,
        message: 'Login successful.',
        user: req.session.user
      });
    });
  });
}

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    panel: 'LEGENDARY FREE PANEL',
    status: 'online'
  });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body || {};

    if (
      typeof username !== 'string' ||
      typeof email !== 'string' ||
      typeof password !== 'string'
    ) {
      return res.status(400).json({
        success: false,
        error: 'Username, email and password are required.'
      });
    }

    const cleanUsername = username.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(cleanUsername)) {
      return res.status(400).json({
        success: false,
        error: 'Username must be 3–24 characters using letters, numbers or underscores.'
      });
    }

    if (
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({
        success: false,
        error: 'Enter a valid email address.'
      });
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
      result = db.prepare(`
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
      `).run(cleanUsername, cleanEmail, passwordHash);
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
      role: 'user'
    };

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: 'Account created, but session creation failed. Please log in.'
        });
      }

      req.session.user = user;

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({
            success: false,
            error: 'Account created, but session saving failed. Please log in.'
          });
        }

        res.status(201).json({
          success: true,
          message: 'Account created successfully.',
          user
        });
      });
    });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({
      success: false,
      error: 'Could not complete registration.'
    });
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

    startUserSession(req, user, res);
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({
      success: false,
      error: 'Could not complete login.'
    });
  }
});

app.get('/api/me', requireLogin, (req, res) => {
  res.json({
    success: true,
    user: req.session.user
  });
});

app.post('/api/auth/logout', requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: 'Could not log out.'
      });
    }

    res.clearCookie('legendary.sid', {
      httpOnly: true,
      secure: 'auto',
      sameSite: 'lax'
    });

    res.json({
      success: true,
      message: 'Logged out successfully.'
    });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`LEGENDARY FREE PANEL backend listening on port ${PORT}`);
});
