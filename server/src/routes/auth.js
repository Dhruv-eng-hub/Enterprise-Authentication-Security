'use strict';

/** Authentication routes: register, verify, login (+2FA), reset, change, logout. */

const express = require('express');
const config = require('../config');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const securityService = require('../services/securityService');
const {
  requireAuth, sessionCookieOptions, authLimiter, resendLimiter, forgotLimiter
} = require('../middleware/security');
const { parseUserAgent, clientIp } = require('../utils/request');

const router = express.Router();

function requestMeta(req) {
  const ua = parseUserAgent(req.headers['user-agent']);
  return { ...ua, ip: clientIp(req) };
}

// Non-sensitive, JS-readable hint so the SPA knows a session exists and can
// skip the /auth/me probe for anonymous visitors (avoids console 401 noise).
// The real session cookie stays HttpOnly.
function setSessionCookie(res, token) {
  res.cookie(config.session.cookieName, token, sessionCookieOptions());
  res.cookie('authed', '1', { sameSite: 'none', secure: true, path: '/' });
}

function clearSessionCookies(res) {
  res.clearCookie(config.session.cookieName, { path: '/' });
  res.clearCookie(config.session.twoFactorCookieName, { path: '/' });
  res.clearCookie('authed', { path: '/' });
}

// ---------------------------------------------------------- register
router.post('/register', authLimiter, async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};
    const result = await authService.register({ name, email, password });
    res.status(201).json({
      message: 'Account created. Please check your inbox to verify your email address.',
      user: result.user,
      ...(result.devEmailUrl ? { devEmailUrl: result.devEmailUrl } : {})
    });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------- email verification
router.post('/verify-email', authLimiter, async (req, res, next) => {
  try {
    const user = await authService.verifyEmail(req.body?.token);
    res.json({ message: 'Your email has been verified. You can now sign in.', user });
  } catch (err) { next(err); }
});

router.post('/resend-verification', resendLimiter, async (req, res, next) => {
  try {
    const result = await authService.resendVerification(req.body?.email);
    res.json(result);
  } catch (err) { next(err); }
});

// ---------------------------------------------------------- login / logout
router.post('/login', authLimiter, async (req, res, next) => {
  try {
    const meta = requestMeta(req);
    const result = await authService.login(
      { email: req.body?.email, password: req.body?.password },
      meta
    );
    if (!result) return res.status(401).json({ message: 'Invalid email or password.' });

    if (result.requiresTwoFactor) {
      res.cookie(config.session.twoFactorCookieName, result.challengeToken, {
        httpOnly: true, sameSite: 'lax', secure: config.isProduction, path: '/',
        maxAge: config.tokens.twoFactorChallengeTtlMinutes * 60_000
      });
      return res.json({ requiresTwoFactor: true, message: 'Enter the code from your authenticator app.' });
    }

    setSessionCookie(res, result.sessionToken);
    return res.json({ message: 'Signed in successfully.', user: result.user });
  } catch (err) { next(err); }
});

router.post('/login/2fa', authLimiter, async (req, res, next) => {
  try {
    const challengeToken = req.cookies?.[config.session.twoFactorCookieName];
    const result = await authService.completeTwoFactorLogin(
      { challengeToken, code: req.body?.code },
      requestMeta(req)
    );
    res.clearCookie(config.session.twoFactorCookieName, { path: '/' });
    setSessionCookie(res, result.sessionToken);
    res.json({ message: 'Signed in successfully.', user: result.user });
  } catch (err) { next(err); }
});

router.post('/logout', requireAuth, (req, res) => {
  sessionService.revokeSession(req.session.id, req.user.id);
  securityService.audit(req.user.id, req.user.email, 'LOGOUT', null, clientIp(req));
  clearSessionCookies(res);
  res.json({ message: 'You have been signed out.' });
});

// ---------------------------------------------------------- current user
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: authService.publicUser(req.user) });
});

// ---------------------------------------------------------- password reset
router.post('/forgot-password', forgotLimiter, async (req, res, next) => {
  try {
    const result = await authService.requestPasswordReset(req.body?.email);
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/reset-password', authLimiter, async (req, res, next) => {
  try {
    const result = await authService.resetPassword(req.body?.token, req.body?.password);
    clearSessionCookies(res);
    res.json(result);
  } catch (err) { next(err); }
});

// ---------------------------------------------------------- change password
router.post('/change-password', requireAuth, async (req, res, next) => {
  try {
    const result = await authService.changePassword(req.user.id, {
      currentPassword: req.body?.currentPassword,
      newPassword: req.body?.newPassword
    });
    clearSessionCookies(res);
    res.json(result);
  } catch (err) { next(err); }
});

// ---------------------------------------------------------- password strength check (no persistence)
router.post('/password-strength', (req, res) => {
  const { scorePassword } = require('../utils/passwordPolicy');
  res.json(scorePassword(String(req.body?.password || '')));
});

module.exports = router;
