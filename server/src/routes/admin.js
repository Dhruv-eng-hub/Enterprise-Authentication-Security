'use strict';

/**
 * Admin security monitoring routes (role-gated).
 * Provides organization-wide visibility: user security posture, login
 * activity across accounts, alerts and the audit trail.
 */

const express = require('express');
const db = require('../db');
const sessionService = require('../services/sessionService');
const securityService = require('../services/securityService');
const { requireAuth, requireAdmin } = require('../middleware/security');
const { nowIso } = require('../utils/crypto');
const { clientIp } = require('../utils/request');

const router = express.Router();
router.use(requireAuth, requireAdmin);

router.get('/overview', (req, res) => {
  const count = (sql) => db.prepare(sql).get().c;
  res.json({
    users: {
      total: count('SELECT COUNT(*) AS c FROM users'),
      verified: count('SELECT COUNT(*) AS c FROM users WHERE email_verified = 1'),
      locked: count(`SELECT COUNT(*) AS c FROM users WHERE locked_until IS NOT NULL AND locked_until > datetime('now')`),
      twoFactor: count('SELECT COUNT(*) AS c FROM users WHERE twofa_enabled = 1')
    },
    sessions: { active: sessionService.countActive() },
    activity: {
      total24h: count(`SELECT COUNT(*) AS c FROM login_activity WHERE created_at >= datetime('now', '-1 day')`),
      failed24h: count(`SELECT COUNT(*) AS c FROM login_activity WHERE status != 'SUCCESS' AND created_at >= datetime('now', '-1 day')`),
      suspicious24h: count(`SELECT COUNT(*) AS c FROM login_activity WHERE status = 'SUSPICIOUS' AND created_at >= datetime('now', '-1 day')`)
    },
    alerts: {
      unreadCritical: count(`SELECT COUNT(*) AS c FROM security_alerts WHERE read_at IS NULL AND severity = 'critical'`)
    },
    loginsByDay: db.prepare(`
      SELECT substr(created_at, 1, 10) AS day,
             SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success,
             SUM(CASE WHEN status != 'SUCCESS' THEN 1 ELSE 0 END) AS failed
      FROM login_activity WHERE created_at >= datetime('now', '-14 days')
      GROUP BY day ORDER BY day
    `).all()
  });
});

router.get('/users', (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.email_verified, u.twofa_enabled,
           u.failed_login_attempts, u.locked_until, u.last_login_at, u.created_at,
           (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.status = 'active') AS active_sessions
    FROM users u ORDER BY u.created_at DESC LIMIT 200
  `).all();
  res.json({ users: rows });
});

/** Unlock a locked account (audited admin action). */
router.post('/users/:id/unlock', (req, res) => {
  const result = db.prepare(
    'UPDATE users SET locked_until = NULL, failed_login_attempts = 0, updated_at = ? WHERE id = ?'
  ).run(nowIso(), req.params.id);
  if (result.changes === 0) return res.status(404).json({ message: 'User not found.' });
  securityService.audit(req.user.id, req.user.email, 'ADMIN_UNLOCKED_ACCOUNT', { targetUserId: Number(req.params.id) }, clientIp(req));
  return res.json({ message: 'Account unlocked.' });
});

/** Force-revoke every session of a user (audited admin action). */
router.post('/users/:id/revoke-sessions', (req, res) => {
  const revoked = sessionService.revokeAllSessions(Number(req.params.id), 'revoked');
  securityService.audit(req.user.id, req.user.email, 'ADMIN_REVOKED_SESSIONS', { targetUserId: Number(req.params.id), revoked }, clientIp(req));
  res.json({ message: `${revoked} session(s) revoked.` });
});

router.get('/login-activity', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const total = db.prepare('SELECT COUNT(*) AS c FROM login_activity').get().c;
  const items = db.prepare(`
    SELECT la.id, la.status, la.reason, la.ip_address, la.device, la.browser, la.os, la.created_at,
           u.email AS user_email
    FROM login_activity la LEFT JOIN users u ON u.id = la.user_id
    ORDER BY la.created_at DESC, la.id DESC LIMIT ? OFFSET ?
  `).all(limit, (page - 1) * limit);
  res.json({ items, page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) });
});

router.get('/alerts', (req, res) => {
  const rows = db.prepare(`
    SELECT sa.id, sa.type, sa.title, sa.message, sa.severity, sa.created_at, sa.read_at, u.email AS user_email
    FROM security_alerts sa JOIN users u ON u.id = sa.user_id
    ORDER BY sa.created_at DESC, sa.id DESC LIMIT 200
  `).all();
  res.json({ alerts: rows });
});

router.get('/audit-logs', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const total = db.prepare('SELECT COUNT(*) AS c FROM audit_logs').get().c;
  const items = db.prepare(`
    SELECT al.action, al.details, al.ip_address, al.created_at, al.actor_email
    FROM audit_logs al ORDER BY al.created_at DESC, al.id DESC LIMIT ? OFFSET ?
  `).all(limit, (page - 1) * limit);
  res.json({ items, page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) });
});

module.exports = router;
