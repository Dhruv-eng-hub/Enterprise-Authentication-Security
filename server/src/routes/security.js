'use strict';

/**
 * Security center routes (authenticated): overview & score, sessions,
 * login activity (+CSV export), alerts, timeline and 2FA management.
 */

const express = require('express');
const db = require('../db');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const securityService = require('../services/securityService');
const { requireAuth, requireVerified, authLimiter } = require('../middleware/security');
const { sha256 } = require('../utils/crypto');
const { clientIp } = require('../utils/request');

const router = express.Router();
router.use(requireAuth, requireVerified);

// ---------------------------------------------------------- overview / score
router.get('/overview', (req, res) => {
  const user = req.user;
  const { score, max, recommendations } = securityService.computeSecurityScore(user);
  const scoreState = securityService.passwordAgeDays(user.password_changed_at);
  res.json({
    user: authService.publicUser(user),
    score: { value: score, max },
    recommendations,
    stats: {
      activeSessions: sessionService.activeCount(user.id),
      unreadAlerts: securityService.unreadAlertCount(user.id),
      failedLogins7d: db.prepare(
        `SELECT COUNT(*) AS c FROM login_activity WHERE user_id = ? AND status IN ('FAILED','LOCKED','BLOCKED')
         AND created_at >= datetime('now', '-7 days')`
      ).get(user.id).c,
      lastLoginAt: user.last_login_at,
      passwordAgeDays: scoreState,
      passwordMaxAgeDays: require('../config').password.maxAgeDays,
      emailVerified: Boolean(user.email_verified),
      twoFactorEnabled: Boolean(user.twofa_enabled)
    }
  });
});

// ---------------------------------------------------------- sessions
router.get('/sessions', (req, res) => {
  const currentHash = req.cookies ? sha256(req.cookies[require('../config').session.cookieName] || '') : '';
  res.json({ sessions: sessionService.listSessions(req.user.id, currentHash) });
});

router.delete('/sessions/:id', (req, res) => {
  if (req.params.id === req.session.id) {
    return res.status(400).json({ message: 'You cannot revoke the session you are currently using. Use sign out instead.' });
  }
  const ok = sessionService.revokeSession(req.params.id, req.user.id);
  if (!ok) return res.status(404).json({ message: 'Session not found or already closed.' });
  securityService.audit(req.user.id, req.user.email, 'SESSION_REVOKED', { sessionId: req.params.id }, clientIp(req));
  return res.json({ message: 'Session revoked. That device has been signed out.' });
});

router.post('/sessions/logout-others', (req, res) => {
  db.prepare(`UPDATE sessions SET status = 'terminated', revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
              WHERE user_id = ? AND status = 'active' AND id != ?`)
    .run(req.user.id, req.session.id);
  securityService.createAlert(req.user.id, 'SESSIONS_REVOKED', 'All other devices were signed out.');
  securityService.audit(req.user.id, req.user.email, 'SESSIONS_LOGOUT_OTHERS', null, clientIp(req));
  res.json({ message: 'All other devices have been signed out.' });
});

router.post('/sessions/logout-all', (req, res) => {
  sessionService.revokeAllSessions(req.user.id, 'revoked');
  securityService.audit(req.user.id, req.user.email, 'SESSIONS_LOGOUT_ALL', null, clientIp(req));
  res.clearCookie(require('../config').session.cookieName, { path: '/' });
  res.json({ message: 'All sessions have been signed out.' });
});

// ---------------------------------------------------------- login activity
router.get('/login-activity', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 10));
  const result = securityService.getLoginActivity(req.user.id, {
    page, limit,
    status: req.query.status,
    search: req.query.search ? String(req.query.search).slice(0, 60) : undefined
  });
  res.json(result);
});

router.get('/login-activity/export', (req, res) => {
  const csv = securityService.activityToCsv(req.user.id, {
    status: req.query.status,
    search: req.query.search ? String(req.query.search).slice(0, 60) : undefined
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="login-activity-${new Date().toISOString().slice(0, 10)}.csv"`);
  securityService.audit(req.user.id, req.user.email, 'LOGIN_ACTIVITY_EXPORTED', null, clientIp(req));
  res.send(csv);
});

// ---------------------------------------------------------- alerts
router.get('/alerts', (req, res) => {
  res.json({ alerts: securityService.listAlerts(req.user.id, { unreadOnly: req.query.unread === '1' }) });
});

router.patch('/alerts/:id/read', (req, res) => {
  const ok = securityService.markAlertRead(req.user.id, req.params.id);
  if (!ok) return res.status(404).json({ message: 'Alert not found or already read.' });
  return res.json({ message: 'Alert marked as read.' });
});

router.patch('/alerts/read-all', (req, res) => {
  const count = securityService.markAllAlertsRead(req.user.id);
  res.json({ message: `${count} alert(s) marked as read.` });
});

// ---------------------------------------------------------- timeline
router.get('/timeline', (req, res) => {
  res.json({ events: securityService.securityTimeline(req.user.id) });
});

// ---------------------------------------------------------- two-factor management
router.post('/2fa/setup', authLimiter, async (req, res, next) => {
  try {
    // force=true discards any pending secret and issues a brand-new key —
    // used when the user's authenticator app holds an entry from an older setup.
    const setup = await authService.setupTwoFactor(req.user.id, { force: Boolean(req.body?.force) });
    securityService.audit(req.user.id, req.user.email, 'TWO_FACTOR_SETUP_STARTED', null, clientIp(req));
    res.json(setup);
  } catch (err) { next(err); }
});

router.post('/2fa/enable', authLimiter, async (req, res, next) => {
  try {
    const { recoveryCodes } = await authService.enableTwoFactor(req.user.id, req.body?.code);
    res.json({
      message: 'Two-factor authentication is now enabled.',
      recoveryCodes
    });
  } catch (err) { next(err); }
});

router.post('/2fa/disable', authLimiter, async (req, res, next) => {
  try {
    await authService.disableTwoFactor(req.user.id, {
      password: req.body?.password,
      code: req.body?.code
    });
    res.json({ message: 'Two-factor authentication has been disabled.' });
  } catch (err) { next(err); }
});

router.post('/2fa/recovery-codes', authLimiter, async (req, res, next) => {
  try {
    if (!req.user.twofa_enabled) return res.status(400).json({ message: 'Enable two-factor authentication first.' });
    const bcrypt = require('bcryptjs');
    const ok = await bcrypt.compare(String(req.body?.password || ''), req.user.password_hash);
    if (!ok) return res.status(401).json({ message: 'Your current password is incorrect.' });
    const recoveryCodes = authService.generateRecoveryCodes(req.user.id);
    securityService.createAlert(req.user.id, 'RECOVERY_CODES_REGENERATED', 'New recovery codes were generated. Old codes are no longer valid.');
    securityService.audit(req.user.id, req.user.email, 'RECOVERY_CODES_REGENERATED', null, clientIp(req));
    return res.json({ recoveryCodes });
  } catch (err) { next(err); }
});

module.exports = router;
