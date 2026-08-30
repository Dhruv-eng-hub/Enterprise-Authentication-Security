'use strict';

/**
 * Session lifecycle service.
 * Sessions are database-backed so they can be revoked instantly and audited.
 * The raw session token never touches the database — only its SHA-256 hash.
 *
 * Expiry model:
 *   expiresAt = min(now + inactivity window, createdAt + max lifetime)
 * and is slid forward on every authenticated request, never beyond max lifetime.
 */

const crypto = require('crypto');
const db = require('../db');
const config = require('../config');
const { sha256, nowIso, minutesFromNow, hoursFromNow } = require('../utils/crypto');

function computeExpiry(createdAtIso) {
  const inactivity = minutesFromNow(config.session.inactivityMinutes);
  const maxLife = new Date(new Date(createdAtIso).getTime() + config.session.maxLifetimeHours * 3_600_000).toISOString();
  return inactivity < maxLife ? inactivity : maxLife;
}

/**
 * Create a session for a user. Returns { sessionId, token }.
 * The token is sent to the client as an HttpOnly cookie only.
 */
function createSession(userId, { device, browser, os, ip }) {
  if (config.session.singleSession) {
    terminateOtherSessions(userId, 'terminated');
  }

  const sessionId = crypto.randomUUID();
  const token = crypto.randomBytes(32).toString('base64url');
  const createdAt = nowIso();

  db.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, device, browser, os, ip_address, status, created_at, last_active_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`
  ).run(sessionId, userId, sha256(token), device, browser, os, ip, createdAt, createdAt, computeExpiry(createdAt));

  return { sessionId, token };
}

/** Resolve a raw session token to an active, unexpired session (or null). */
function findByToken(token) {
  if (!token) return null;
  const session = db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(sha256(token));
  if (!session || session.status !== 'active') return null;

  const now = Date.now();
  if (new Date(session.expires_at).getTime() <= now) {
    db.prepare(`UPDATE sessions SET status = 'expired', revoked_at = ? WHERE id = ?`).run(nowIso(), session.id);
    return null;
  }

  // Slide the inactivity window forward, capped at the absolute max lifetime.
  const newExpiry = computeExpiry(session.created_at);
  db.prepare('UPDATE sessions SET last_active_at = ?, expires_at = ? WHERE id = ?')
    .run(nowIso(), newExpiry, session.id);

  return { ...session, expires_at: newExpiry };
}

function terminateOtherSessions(userId, reason = 'revoked') {
  db.prepare(
    `UPDATE sessions SET status = ?, revoked_at = ? WHERE user_id = ? AND status = 'active'`
  ).run(reason, nowIso(), userId);
}

function revokeSession(sessionId, userId) {
  const result = db.prepare(
    `UPDATE sessions SET status = 'revoked', revoked_at = ? WHERE id = ? AND user_id = ? AND status = 'active'`
  ).run(nowIso(), sessionId, userId);
  return result.changes > 0;
}

/** Revoke every session of a user (password reset / logout-all). */
function revokeAllSessions(userId, reason = 'revoked') {
  const result = db.prepare(
    `UPDATE sessions SET status = ?, revoked_at = ? WHERE user_id = ? AND status = 'active'`
  ).run(reason, nowIso(), userId);
  return result.changes;
}

/** List sessions for a user, marking the one matching currentToken. */
function listSessions(userId, currentTokenHash) {
  expireStale(userId);
  return db.prepare(
    `SELECT id, device, browser, os, ip_address, status, created_at, last_active_at, expires_at, revoked_at,
            CASE WHEN token_hash = ? THEN 1 ELSE 0 END AS is_current
     FROM sessions WHERE user_id = ?
     ORDER BY last_active_at DESC LIMIT 50`
  ).all(currentTokenHash || '', userId);
}

function expireStale(userId) {
  db.prepare(
    `UPDATE sessions SET status = 'expired' WHERE user_id = ? AND status = 'active' AND expires_at <= ?`
  ).run(userId, nowIso());
}

function activeCount(userId) {
  expireStale(userId);
  return db.prepare(`SELECT COUNT(*) AS c FROM sessions WHERE user_id = ? AND status = 'active'`).get(userId).c;
}

function countActive() {
  db.prepare(`UPDATE sessions SET status = 'expired' WHERE status = 'active' AND expires_at <= ?`).run(nowIso());
  return db.prepare(`SELECT COUNT(*) AS c FROM sessions WHERE status = 'active'`).get().c;
}

module.exports = {
  createSession,
  findByToken,
  terminateOtherSessions,
  revokeSession,
  revokeAllSessions,
  listSessions,
  activeCount,
  countActive
};
