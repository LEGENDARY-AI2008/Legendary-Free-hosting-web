'use strict';

const crypto = require('crypto');

/*
 * Encrypts bot environment variables (bot tokens, API keys) at rest.
 * Key comes from BOT_ENV_KEY, falling back to SESSION_SECRET.
 * If the key is changed, old values cannot be read; set BOT_ENV_KEY once
 * and keep it stable.
 */

let cachedKey;

function getKey() {
  if (!cachedKey) {
    const secret = process.env.BOT_ENV_KEY || process.env.SESSION_SECRET || '';
    cachedKey = crypto.scryptSync(secret, 'legendary-panel-bot-env-v1', 32);
  }
  return cachedKey;
}

function encryptVars(vars) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(vars), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decryptVars(blob) {
  if (!blob) return {};
  try {
    const raw = Buffer.from(blob, 'base64');
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const enc = raw.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), iv);
    decipher.setAuthTag(tag);
    const text = Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
    const obj = JSON.parse(text);
    return obj && typeof obj === 'object' ? obj : {};
  } catch (_) {
    return {};
  }
}

const RESERVED = new Set([
  'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'PWD', 'OLDPWD', 'TMPDIR',
  'TEMP', 'TMP', 'IFS', 'HOSTNAME', 'PORT', 'SESSION_SECRET', 'BOT_ENV_KEY'
]);

function validateVars(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { error: 'Variables must be an object of NAME: value pairs.' };
  }
  const entries = Object.entries(input);
  if (entries.length > 30) return { error: 'You can set at most 30 variables.' };

  const out = {};
  for (const [key, value] of entries) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(key)) {
      return { error: 'Invalid variable name: ' + String(key).slice(0, 40) };
    }
    const upper = key.toUpperCase();
    if (RESERVED.has(upper) || upper.startsWith('NODE_') || upper.startsWith('LD_') ||
        upper.startsWith('DYLD_') || upper.startsWith('NPM_')) {
      return { error: 'That variable name is reserved: ' + key };
    }
    if (typeof value !== 'string' || value.length > 4096 || value.includes('\0')) {
      return { error: 'Invalid value for ' + key + ' (text up to 4096 characters).' };
    }
    out[key] = value;
  }
  return { vars: out };
}

module.exports = { encryptVars, decryptVars, validateVars };
