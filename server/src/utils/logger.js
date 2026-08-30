'use strict';

/**
 * Minimal structured logger that redacts sensitive fields.
 * Passwords, tokens, hashes, cookies and authorization headers are never logged.
 */

const SENSITIVE_KEYS = new Set([
  'password', 'newpassword', 'currentpassword', 'confirmpassword',
  'token', 'code', 'secret', 'authorization', 'cookie', 'sessiontoken',
  'recoverycodes', 'passwordhash', 'tokenhash', 'sid'
]);

function redact(value) {
  if (value === null || typeof value !== 'object') return value;
  const out = Array.isArray(value) ? [] : {};
  for (const [key, val] of Object.entries(value)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      out[key] = '[REDACTED]';
    } else if (val && typeof val === 'object') {
      out[key] = redact(val);
    } else {
      out[key] = val;
    }
  }
  return out;
}

function log(level, message, meta) {
  const line = `[${new Date().toISOString()}] ${level.toUpperCase()} ${message}`;
  if (meta !== undefined) {
    // eslint-disable-next-line no-console
    console[level === 'error' ? 'error' : 'log'](line, JSON.stringify(redact(meta)));
  } else {
    // eslint-disable-next-line no-console
    console[level === 'error' ? 'error' : 'log'](line);
  }
}

module.exports = {
  info: (msg, meta) => log('info', msg, meta),
  warn: (msg, meta) => log('warn', msg, meta),
  error: (msg, meta) => log('error', msg, meta),
  redact
};
