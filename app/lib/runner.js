'use strict';

/*
 * Bot runner: installs dependencies and runs each bot as a separate,
 * sandboxed Node.js process.
 *
 * Isolation (best effort, same machine):
 *  - Node's permission model: a bot can read/write ONLY its own folder.
 *    It cannot read the panel's database, secrets, other bots, or /proc,
 *    and cannot spawn child processes.
 *  - The bot gets a clean environment: none of the panel's variables.
 *  - Memory cap (BOT_MEM_MB, default 256) is enforced by polling.
 *  - At most MAX_RUNNING_BOTS (default 2) run at once.
 *
 * This is NOT a container. It does not limit CPU or network access.
 */

const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const MEM_LIMIT_MB = Number(process.env.BOT_MEM_MB) || 256;
const MAX_RUNNING = Number(process.env.MAX_RUNNING_BOTS) || 2;
const MAX_DISK_MB = Number(process.env.BOT_MAX_DISK_MB) || 300;
const LOG_MAX_BYTES = 1024 * 1024;
const INSTALL_TIMEOUT_MS = 5 * 60 * 1000;
const STOP_GRACE_MS = 5000;
const MEM_POLL_MS = 10000;

function detectPermissionFlag() {
  for (const flag of ['--permission', '--experimental-permission']) {
    const r = spawnSync(process.execPath, [flag, '-e', '0'], { timeout: 10000 });
    if (r.status === 0) return flag;
  }
  return null;
}

function dirSizeBytes(root) {
  let total = 0;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let items;
    try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const item of items) {
      const full = path.join(dir, item.name);
      if (item.isDirectory()) stack.push(full);
      else if (item.isFile()) {
        try { total += fs.statSync(full).size; } catch (_) {}
      }
    }
  }
  return total;
}

function killGroup(child, signal) {
  try {
    process.kill(-child.pid, signal);
  } catch (_) {
    try { child.kill(signal); } catch (__) {}
  }
}

function createRunner({ db, botsRoot, loadEnv }) {
  const permissionFlag = detectPermissionFlag();
  const procs = new Map();     // botId -> { child, stopping, reason, secrets, startedAt }
  const installs = new Map();  // botId -> child
  const logSizes = new Map();
  let installChain = Promise.resolve();

  fs.mkdirSync(botsRoot, { recursive: true });

  function paths(id) {
    const dir = path.join(botsRoot, String(id));
    return { dir, code: path.join(dir, 'code'), log: path.join(dir, 'panel.log') };
  }

  function setStatus(id, status, lastExit) {
    db.prepare(
      "UPDATE bots SET status = ?, last_exit = ?, updated_at = datetime('now') WHERE id = ?"
    ).run(status, lastExit == null ? null : String(lastExit).slice(0, 300), id);
  }

  // ---------- logs ----------
  function writeLog(id, text, secrets) {
    if (!text) return;
    let out = text;
    for (const s of secrets || []) {
      if (typeof s === 'string' && s.length >= 6) out = out.split(s).join('***');
    }
    const { dir, log } = paths(id);
    try {
      fs.mkdirSync(dir, { recursive: true });
      let size = logSizes.has(id)
        ? logSizes.get(id)
        : (fs.existsSync(log) ? fs.statSync(log).size : 0);
      const buf = Buffer.from(out);
      if (size + buf.length > LOG_MAX_BYTES) {
        try { fs.renameSync(log, log + '.1'); } catch (_) {}
        size = 0;
      }
      fs.appendFileSync(log, buf);
      logSizes.set(id, size + buf.length);
    } catch (_) {}
  }

  function sysLog(id, message) {
    writeLog(id, '[panel ' + new Date().toISOString() + '] ' + message + '\n');
  }

  function tail(id, maxLines) {
    const { log } = paths(id);
    try {
      const st = fs.statSync(log);
      const len = Math.min(st.size, 64 * 1024);
      const buf = Buffer.alloc(len);
      const fd = fs.openSync(log, 'r');
      fs.readSync(fd, buf, 0, len, st.size - len);
      fs.closeSync(fd);
      const lines = buf.toString('utf8').split('\n');
      if (st.size > len) lines.shift();
      return lines.slice(-maxLines).join('\n');
    } catch (_) {
      return '';
    }
  }

  // ---------- install ----------
  function doInstall(id) {
    return new Promise((resolve) => {
      const { dir, code } = paths(id);
      let finished = false;

      const done = (ok, reason) => {
        if (finished) return;
        finished = true;
        installs.delete(id);
        const size = dirSizeBytes(dir);
        db.prepare("UPDATE bots SET size_bytes = ? WHERE id = ?").run(size, id);
        setStatus(id, ok ? 'stopped' : 'install_failed', ok ? null : reason);
        sysLog(id, ok ? 'Ready. Press Start to run your bot.' : 'Install failed: ' + reason);
        resolve();
      };

      let pkg = null;
      try { pkg = JSON.parse(fs.readFileSync(path.join(code, 'package.json'), 'utf8')); } catch (_) {}
      const hasDeps = pkg && pkg.dependencies && Object.keys(pkg.dependencies).length > 0;
      if (!hasDeps) {
        sysLog(id, 'No dependencies to install.');
        return done(true);
      }

      sysLog(id, 'Installing dependencies (scripts disabled for safety)...');
      const env = {
        PATH: process.env.PATH,
        HOME: dir,
        npm_config_cache: path.join(dir, '.npm'),
        npm_config_update_notifier: 'false',
        npm_config_fund: 'false',
        npm_config_audit: 'false',
        NODE_OPTIONS: '--max-old-space-size=192',
        CI: 'true'
      };

      let child;
      try {
        child = spawn('npm', ['install', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'], {
          cwd: code, env, stdio: ['ignore', 'pipe', 'pipe'], detached: true
        });
      } catch (err) {
        return done(false, 'npm is not available on this server.');
      }
      installs.set(id, child);

      const timer = setTimeout(() => {
        killGroup(child, 'SIGKILL');
        done(false, 'Install took longer than 5 minutes.');
      }, INSTALL_TIMEOUT_MS);

      child.stdout.on('data', (d) => writeLog(id, d.toString()));
      child.stderr.on('data', (d) => writeLog(id, d.toString()));
      child.on('error', () => { clearTimeout(timer); done(false, 'Could not run npm.'); });
      child.on('exit', (codeNum) => {
        clearTimeout(timer);
        if (finished) return;
        if (codeNum !== 0) return done(false, 'npm install failed (see logs).');
        const size = dirSizeBytes(dir);
        if (size > MAX_DISK_MB * 1024 * 1024) {
          return done(false, 'Project is larger than ' + MAX_DISK_MB + ' MB after install.');
        }
        done(true);
      });
    });
  }

  function install(id) {
    installChain = installChain.then(() => doInstall(id)).catch(() => {});
    return installChain;
  }

  function cancelInstall(id) {
    const child = installs.get(id);
    if (child) killGroup(child, 'SIGKILL');
  }

  // ---------- run ----------
  function buildEnv(dir, userVars) {
    return Object.assign({}, userVars, {
      PATH: process.env.PATH,
      HOME: dir,
      NODE_ENV: 'production',
      TZ: process.env.TZ || 'UTC',
      LANG: 'C.UTF-8'
    });
  }

  function start(bot) {
    if (procs.has(bot.id)) return { ok: false, error: 'This bot is already running.' };
    if (!permissionFlag) {
      return { ok: false, error: 'This server cannot sandbox bots safely, so starting is disabled.' };
    }
    if (procs.size >= MAX_RUNNING) {
      return {
        ok: false,
        error: 'The server can run at most ' + MAX_RUNNING + ' bots at once. Stop another bot first.'
      };
    }

    const { dir, code } = paths(bot.id);
    const entryAbs = path.resolve(code, bot.entry || '');
    if (!bot.entry || !entryAbs.startsWith(code + path.sep) || !fs.existsSync(entryAbs)) {
      return { ok: false, error: 'The bot entry file was not found.' };
    }

    const vars = loadEnv(bot);
    const secrets = Object.values(vars);
    const heapMb = Math.max(64, Math.floor(MEM_LIMIT_MB * 0.75));
    const args = [
      permissionFlag,
      '--allow-fs-read=' + dir,
      '--allow-fs-write=' + dir,
      '--max-old-space-size=' + heapMb,
      entryAbs
    ];

    let child;
    try {
      child = spawn(process.execPath, args, {
        cwd: code,
        env: buildEnv(dir, vars),
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: true
      });
    } catch (err) {
      return { ok: false, error: 'Could not start the bot process.' };
    }

    const entry = { child, stopping: false, reason: null, secrets, startedAt: Date.now() };
    procs.set(bot.id, entry);

    db.prepare(
      "UPDATE bots SET status = 'running', last_started_at = datetime('now'), last_exit = NULL, updated_at = datetime('now') WHERE id = ?"
    ).run(bot.id);
    sysLog(bot.id, 'Starting: node ' + path.relative(code, entryAbs));

    child.stdout.on('data', (d) => writeLog(bot.id, d.toString(), secrets));
    child.stderr.on('data', (d) => writeLog(bot.id, d.toString(), secrets));

    child.on('error', (err) => {
      if (procs.get(bot.id) !== entry) return;
      procs.delete(bot.id);
      sysLog(bot.id, 'Process error: ' + err.message);
      setStatus(bot.id, 'crashed', 'Could not start: ' + err.message);
    });

    child.on('exit', (exitCode, signal) => {
      if (procs.get(bot.id) !== entry) return;
      procs.delete(bot.id);
      let status;
      let reason;
      if (entry.reason) {
        status = 'crashed';
        reason = entry.reason;
      } else if (entry.stopping) {
        status = 'stopped';
        reason = 'Stopped by request.';
      } else if (exitCode === 0) {
        status = 'stopped';
        reason = 'Exited normally (code 0).';
      } else {
        status = 'crashed';
        reason = signal ? 'Killed by ' + signal + '.' : 'Exited with code ' + exitCode + '.';
      }
      sysLog(bot.id, reason);
      setStatus(bot.id, status, reason);
    });

    return { ok: true };
  }

  function stop(id) {
    const entry = procs.get(id);
    if (!entry) return Promise.resolve(false);
    entry.stopping = true;
    return new Promise((resolve) => {
      const timer = setTimeout(() => killGroup(entry.child, 'SIGKILL'), STOP_GRACE_MS);
      entry.child.once('exit', () => { clearTimeout(timer); resolve(true); });
      killGroup(entry.child, 'SIGTERM');
    });
  }

  async function restart(bot) {
    await stop(bot.id);
    return start(bot);
  }

  function isRunning(id) {
    return procs.has(id);
  }

  function rssMb(pid) {
    try {
      const m = /VmRSS:\s+(\d+)\s+kB/.exec(fs.readFileSync('/proc/' + pid + '/status', 'utf8'));
      return m ? Math.round(Number(m[1]) / 1024) : null;
    } catch (_) {
      return null;
    }
  }

  function usage(id) {
    const entry = procs.get(id);
    if (!entry) return null;
    return {
      memoryMb: rssMb(entry.child.pid),
      uptimeSec: Math.floor((Date.now() - entry.startedAt) / 1000)
    };
  }

  // Enforce the memory cap.
  const monitor = setInterval(() => {
    for (const [id, entry] of procs) {
      const mb = rssMb(entry.child.pid);
      if (mb !== null && mb > MEM_LIMIT_MB && !entry.reason) {
        entry.reason = 'Stopped: used more than the ' + MEM_LIMIT_MB + ' MB memory limit.';
        sysLog(id, entry.reason);
        killGroup(entry.child, 'SIGKILL');
      }
    }
  }, MEM_POLL_MS);
  monitor.unref();

  function shutdownAll() {
    clearInterval(monitor);
    for (const entry of procs.values()) killGroup(entry.child, 'SIGKILL');
    for (const child of installs.values()) killGroup(child, 'SIGKILL');
  }

  // Processes do not survive a panel restart; fix any stale state.
  function recover() {
    db.prepare(
      "UPDATE bots SET status = 'stopped', last_exit = 'Stopped because the panel restarted.' WHERE status IN ('running', 'starting')"
    ).run();
    db.prepare(
      "UPDATE bots SET status = 'install_failed', last_exit = 'Install was interrupted by a panel restart. Delete and upload again.' WHERE status = 'installing'"
    ).run();
  }

  return {
    paths, start, stop, restart, isRunning, usage, install, cancelInstall,
    tail, sysLog, shutdownAll, recover,
    runningCount: () => procs.size,
    sandboxAvailable: !!permissionFlag,
    limits: { memoryMb: MEM_LIMIT_MB, maxRunning: MAX_RUNNING, maxDiskMb: MAX_DISK_MB }
  };
}

module.exports = { createRunner };
