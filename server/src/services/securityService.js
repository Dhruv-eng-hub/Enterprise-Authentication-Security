'use strict';

/**
 * Security intelligence service:
 *  - login activity recording
 *  - security alerts
 *  - audit logs for all sensitive actions
 *  - anomaly detection (new device / new browser / unusual IP / off-hours)
 *  - security score + recommendations
 *  - unified security event timeline
 */

const db = require('../db');
const config = require('../config');
const logger = require('../utils/logger');
const { nowIso } = require('../utils/crypto');
const sessionService = require('./sessionService');

// ---------------------------------------------------------------- activity

function recordLoginActivity({ userId, email, status, reason, ip, device, browser, os, location, sessionId }) {
  db.prepare(
    `INSERT INTO login_activity (user_id, email, status, reason, ip_address, device, browser, os, location, session_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(userId || null, email || null, status, reason || null, ip, device, browser, os, location || null, sessionId || null);
  logger.info(`login-activity status=${status}`, { userId, email, ip });
}

function getLoginActivity(userId, { page = 1, limit = 10, status, search } = {}) {
  const where = ['user_id = ?'];
  const params = [userId];
  if (status && ['SUCCESS', 'FAILED', 'BLOCKED', 'LOCKED', 'SUSPICIOUS'].includes(status)) {
    where.push('status = ?');
    params.push(status);
  }
  if (search) {
    where.push('(browser LIKE ? OR os LIKE ? OR device LIKE ? OR ip_address LIKE ?)');
    const like = `%${search}%`;
    params.push(like, like, like, like);
  }
  const whereSql = where.join(' AND ');
  const total = db.prepare(`SELECT COUNT(*) AS c FROM login_activity WHERE ${whereSql}`).get(...params).c;
  const rows = db.prepare(
    `SELECT id, status, reason, ip_address, device, browser, os, location, session_id, created_at
     FROM login_activity WHERE ${whereSql}
     ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
  ).all(...params, limit, (page - 1) * limit);
  return { items: rows, page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) };
}

function activityToCsv(userId, { status, search } = {}) {
  const { items } = getLoginActivity(userId, { page: 1, limit: 10000, status, search });
  const escape = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const header = 'Timestamp,Status,Reason,IP Address,Device,Browser,Operating System,Location';
  const lines = items.map((r) =>
    [r.created_at, r.status, r.reason, r.ip_address, r.device, r.browser, r.os, r.location].map(escape).join(',')
  );
  return [header, ...lines].join('\n');
}

// ---------------------------------------------------------------- alerts

const ALERT_TYPES = {
  NEW_DEVICE_LOGIN: { title: 'New device login detected', severity: 'warning' },
  MULTIPLE_FAILED_LOGINS: { title: 'Multiple failed login attempts', severity: 'warning' },
  ACCOUNT_LOCKED: { title: 'Account temporarily locked', severity: 'critical' },
  ACCOUNT_UNLOCKED: { title: 'Account lockout expired', severity: 'info' },
  PASSWORD_CHANGED: { title: 'Password changed', severity: 'info' },
  PASSWORD_RESET_REQUESTED: { title: 'Password reset requested', severity: 'info' },
  PASSWORD_RESET_COMPLETED: { title: 'Password reset completed', severity: 'critical' },
  SESSIONS_REVOKED: { title: 'Sessions signed out', severity: 'info' },
  SUSPICIOUS_LOGIN: { title: 'Suspicious login behavior', severity: 'critical' },
  TWO_FACTOR_ENABLED: { title: 'Two-factor authentication enabled', severity: 'info' },
  TWO_FACTOR_DISABLED: { title: 'Two-factor authentication disabled', severity: 'warning' },
  RECOVERY_CODES_REGENERATED: { title: 'Recovery codes regenerated', severity: 'info' }
};

function createAlert(userId, type, message, severityOverride) {
  const def = ALERT_TYPES[type] || { title: type, severity: 'info' };
  db.prepare(
    `INSERT INTO security_alerts (user_id, type, title, message, severity) VALUES (?, ?, ?, ?, ?)`
  ).run(userId, type, def.title, message, severityOverride || def.severity);
}

function listAlerts(userId, { unreadOnly = false, limit = 50 } = {}) {
  return db.prepare(
    `SELECT id, type, title, message, severity, created_at, read_at FROM security_alerts
     WHERE user_id = ? ${unreadOnly ? 'AND read_at IS NULL' : ''}
     ORDER BY created_at DESC, id DESC LIMIT ?`
  ).all(userId, limit);
}

function markAlertRead(userId, alertId) {
  return db.prepare('UPDATE security_alerts SET read_at = ? WHERE user_id = ? AND id = ? AND read_at IS NULL')
    .run(nowIso(), userId, alertId).changes > 0;
}

function markAllAlertsRead(userId) {
  return db.prepare('UPDATE security_alerts SET read_at = ? WHERE user_id = ? AND read_at IS NULL')
    .run(nowIso(), userId).changes;
}

function unreadAlertCount(userId) {
  return db.prepare('SELECT COUNT(*) AS c FROM security_alerts WHERE user_id = ? AND read_at IS NULL').get(userId).c;
}

// ---------------------------------------------------------------- audit

function audit(userId, actorEmail, action, details, ip) {
  db.prepare('INSERT INTO audit_logs (user_id, actor_email, action, details, ip_address) VALUES (?, ?, ?, ?, ?)')
    .run(userId || null, actorEmail || null, action, details ? JSON.stringify(details) : null, ip || null);
}

// ---------------------------------------------------------------- anomaly

/**
 * Detect login anomalies by comparing against the user's history:
 * new browser, new OS, never-seen IP, or off-hours login (00:00–05:00 local).
 * Returns { suspicious, reasons }.
 */
function analyzeLoginAnomaly(userId, { browser, os, ip }) {
  const reasons = [];
  const history = db.prepare(
    `SELECT browser, os, ip_address FROM login_activity
     WHERE user_id = ? AND status IN ('SUCCESS','SUSPICIOUS') ORDER BY created_at DESC LIMIT 100`
  ).all(userId);

  if (history.length >= 1) {
    const knownBrowsers = new Set(history.map((h) => h.browser));
    const knownOs = new Set(history.map((h) => h.os));
    const knownIps = new Set(history.map((h) => h.ip_address));
    if (!knownBrowsers.has(browser)) reasons.push('new browser');
    if (!knownOs.has(os)) reasons.push('new operating system');
    if (!knownIps.has(ip)) reasons.push('unrecognized IP address');
  }

  const hour = new Date().getHours();
  if (hour >= 0 && hour < 5) reasons.push('unusual sign-in time');

  return { suspicious: reasons.length > 0, reasons };
}

// ---------------------------------------------------------------- score

function passwordAgeDays(passwordChangedAt) {
  if (!passwordChangedAt) return 999;
  return Math.floor((Date.now() - new Date(passwordChangedAt).getTime()) / 86_400_000);
}

function computeSecurityScore(user) {
  const recommendations = [];
  let score = 0;

  if (user.email_verified) {
    score += 25;
  } else {
    recommendations.push({ id: 'verify-email', text: 'Verify your email address', points: 25 });
  }

  if (user.twofa_enabled) {
    score += 25;
  } else {
    recommendations.push({ id: 'enable-2fa', text: 'Enable two-factor authentication', points: 25 });
  }

  const ageDays = passwordAgeDays(user.password_changed_at);
  if (config.password.maxAgeDays > 0 && ageDays > config.password.maxAgeDays) {
    recommendations.push({ id: 'rotate-password', text: `Your password is ${ageDays} days old — rotate it (policy: ${config.password.maxAgeDays} days)`, points: 15 });
  } else {
    score += 15;
  }

  const recentFailures = db.prepare(
    `SELECT COUNT(*) AS c FROM login_activity WHERE user_id = ? AND status IN ('FAILED','LOCKED','BLOCKED')
     AND created_at >= datetime('now', '-7 days')`
  ).get(user.id).c;
  if (recentFailures === 0) {
    score += 15;
  } else {
    recommendations.push({ id: 'review-failures', text: `Review ${recentFailures} failed sign-in attempt(s) in the last 7 days`, points: 15 });
  }

  const recentSuspicious = db.prepare(
    `SELECT COUNT(*) AS c FROM security_alerts WHERE user_id = ? AND severity = 'critical'
     AND created_at >= datetime('now', '-7 days')`
  ).get(user.id).c;
  if (recentSuspicious === 0) {
    score += 20;
  } else {
    recommendations.push({ id: 'review-alerts', text: 'Review recent critical security alerts', points: 20 });
  }

  return { score, max: 100, recommendations };
}

// ---------------------------------------------------------------- timeline

function securityTimeline(userId, limit = 50) {
  const events = [];
  for (const r of db.prepare(
    `SELECT status, reason, browser, os, ip_address, created_at FROM login_activity
     WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`
  ).all(userId, limit)) {
    events.push({
      at: r.created_at,
      category: 'activity',
      severity: r.status === 'SUCCESS' ? 'info' : r.status === 'SUSPICIOUS' ? 'critical' : 'warning',
      title: r.status === 'SUCCESS' ? 'Successful sign-in' : `Sign-in ${r.status.toLowerCase()}`,
      detail: [r.browser, r.os].filter(Boolean).join(' • ') + (r.reason ? ` — ${r.reason}` : '')
    });
  }
  for (const a of db.prepare(
    'SELECT title, message, severity, created_at FROM security_alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT ?'
  ).all(userId, limit)) {
    events.push({ at: a.created_at, category: 'alert', severity: a.severity, title: a.title, detail: a.message });
  }
  for (const l of db.prepare(
    'SELECT action, details, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?'
  ).all(userId, limit)) {
    events.push({ at: l.created_at, category: 'audit', severity: 'info', title: l.action.replaceAll('_', ' '), detail: l.details || '' });
  }
  return events.sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, limit);
}

module.exports = {
  recordLoginActivity,
  getLoginActivity,
  activityToCsv,
  createAlert,
  listAlerts,
  markAlertRead,
  markAllAlertsRead,
  unreadAlertCount,
  audit,
  analyzeLoginAnomaly,
  computeSecurityScore,
  passwordAgeDays,
  securityTimeline
};
