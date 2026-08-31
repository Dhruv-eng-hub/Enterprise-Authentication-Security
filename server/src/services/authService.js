'use strict';

/**
 * Authentication service — the heart of the security module.
 * Implements registration + email verification, login with progressive
 * lockout and anomaly detection, optional TOTP 2FA with recovery codes,
 * secure password reset and password-change policy enforcement.
 */

const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const db = require('../db');
const config = require('../config');

// Accept codes a few 30-second steps away from “now” to tolerate phone clock
// drift and users typing a code just as it rotates. Configurable via TOTP_WINDOW.
authenticator.options = { window: config.totp.window };
const logger = require('../utils/logger');
const {
  randomToken, sha256, encrypt, decrypt, nowIso, minutesFromNow
} = require('../utils/crypto');
const { validatePassword } = require('../utils/passwordPolicy');
const { isEmail, sanitizeText } = require('../utils/request');
const sessionService = require('./sessionService');
const securityService = require('./securityService');
const emailService = require('./emailService');

// Pre-computed dummy hash so unknown emails take the same time as known ones.
const DUMMY_HASH = bcrypt.hashSync('invalid-password-timing-equalizer', 10);

const EMAIL_NOT_VERIFIED = 'EMAIL_NOT_VERIFIED';
const TWO_FACTOR_REQUIRED = 'TWO_FACTOR_REQUIRED';

// ================================================================ users

function findUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).trim().toLowerCase());
}

function findUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

/** Public-safe user object — never exposes hashes, tokens or security internals. */
function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    emailVerified: Boolean(user.email_verified),
    twoFactorEnabled: Boolean(user.twofa_enabled),
    lastLoginAt: user.last_login_at,
    passwordChangedAt: user.password_changed_at,
    createdAt: user.created_at
  };
}

// ================================================================ register

async function register({ name, email, password }) {
  const cleanName = sanitizeText(name, 80);
  const cleanEmail = String(email).trim().toLowerCase();

  if (!cleanName || cleanName.length < 2) {
    throw apiError(400, 'Please provide your full name.');
  }
  if (!isEmail(cleanEmail)) {
    throw apiError(400, 'Please provide a valid email address.');
  }

  const policy = validatePassword(password, { email: cleanEmail, name: cleanName });
  if (!policy.valid) {
    throw apiError(400, policy.errors.join(' '), { errors: policy.errors });
  }

  if (findUserByEmail(cleanEmail)) {
    throw apiError(409, 'An account with this email already exists. Try signing in instead.');
  }

  const passwordHash = await bcrypt.hash(password, config.password.bcryptRounds);
  const now = nowIso();
  const result = db.prepare(
    `INSERT INTO users (name, email, password_hash, role, email_verified, password_changed_at, created_at, updated_at)
     VALUES (?, ?, ?, 'user', 0, ?, ?, ?)`
  ).run(cleanName, cleanEmail, passwordHash, now, now, now);

  const userId = result.lastInsertRowid;
  pushPasswordHistory(userId, passwordHash);
  securityService.audit(userId, cleanEmail, 'USER_REGISTERED', { name: cleanName });
  logger.info(`user registered id=${userId}`);

  const devInfo = await issueEmailVerification({ id: userId, name: cleanName, email: cleanEmail });
  return { user: publicUser(findUserById(userId)), ...devInfo };
}

// ================================================================ email verification

async function issueEmailVerification(user) {
  db.prepare(
    'DELETE FROM email_verification_tokens WHERE user_id = ? AND used_at IS NULL'
  ).run(user.id);

  const token = randomToken(32);

  db.prepare(
    'INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
  ).run(
    user.id,
    sha256(token),
    minutesFromNow(config.tokens.emailVerificationTtlMinutes)
  );

  const url = `${config.appUrl}/verify-email?token=${token}`;

  try {
    await emailService.verificationEmail({
      to: user.email,
      name: user.name,
      url
    });
  } catch {
    // Delivery failure should not block registration.
  }

  securityService.audit(
    user.id,
    user.email,
    'VERIFICATION_EMAIL_SENT',
    null
  );

  // Show the verification link whenever SMTP is not configured.
  if (!config.smtp.host) {
    logger.info(`[verification-link] ${url}`);
    return { devEmailUrl: url };
  }

  return {};
}
async function verifyEmail(token) {
  const row = db.prepare('SELECT * FROM email_verification_tokens WHERE token_hash = ?').get(sha256(String(token || '')));
  if (!row) throw apiError(400, 'This verification link is invalid. Please request a new one.');
  if (row.used_at) throw apiError(400, 'This verification link has already been used.');
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    throw apiError(400, 'This verification link has expired. Please request a new one.', { expired: true });
  }

  const user = findUserById(row.user_id);
  db.prepare('UPDATE email_verification_tokens SET used_at = ? WHERE id = ?').run(nowIso(), row.id);
  db.prepare('UPDATE users SET email_verified = 1, email_verified_at = ?, updated_at = ? WHERE id = ?')
    .run(nowIso(), nowIso(), user.id);
  securityService.audit(user.id, user.email, 'EMAIL_VERIFIED', null);
  logger.info(`email verified userId=${user.id}`);
  return publicUser(findUserById(user.id));
}

async function resendVerification(email) {
  const cleanEmail = String(email || '').trim().toLowerCase();
  const user = findUserByEmail(cleanEmail);
  // Always answer the same way — never reveal whether the account exists.
  const generic = { message: 'If an account exists with this email and is unverified, a new verification link has been sent.' };
  if (!user || user.email_verified) return generic;
  const devInfo = await issueEmailVerification(user);
  return { ...generic, ...devInfo };
}

// ================================================================ login

async function login({ email, password }, reqMeta) {
  const cleanEmail = String(email || '').trim().toLowerCase();
  const user = findUserByEmail(cleanEmail);

  const equalized = await bcrypt.compare(password || '', user ? user.password_hash : DUMMY_HASH);

  if (!user || !equalized) {
    await handleFailedLogin(user, cleanEmail, user ? 'invalid credentials' : 'unknown email', reqMeta);
    return null;
  }

  // --- account lockout check
  if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
    const minutes = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60_000);
    securityService.recordLoginActivity({
      userId: user.id, email: cleanEmail, status: 'LOCKED',
      reason: 'account temporarily locked', ...reqMeta
    });
    throw apiError(423, `Your account has been temporarily locked due to multiple unsuccessful login attempts. Please try again in about ${minutes} minute(s).`, { code: 'ACCOUNT_LOCKED' });
  }

  // --- email verification gate
  if (!user.email_verified) {
    securityService.recordLoginActivity({
      userId: user.id, email: cleanEmail, status: 'BLOCKED',
      reason: 'email not verified', ...reqMeta
    });
    throw apiError(403, 'Please verify your email address before signing in.', { code: EMAIL_NOT_VERIFIED });
  }

  // --- success path
  db.prepare(
    'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, lock_count = 0, last_login_at = ?, last_login_ip = ?, updated_at = ? WHERE id = ?'
  ).run(nowIso(), reqMeta.ip, nowIso(), user.id);

  const anomaly = securityService.analyzeLoginAnomaly(user.id, reqMeta);

  if (user.twofa_enabled) {
    securityService.recordLoginActivity({
      userId: user.id, email: cleanEmail, status: anomaly.suspicious ? 'SUSPICIOUS' : 'SUCCESS',
      reason: anomaly.suspicious ? anomaly.reasons.join(', ') : 'pending 2FA', ...reqMeta
    });
    if (anomaly.suspicious) {
      securityService.createAlert(user.id, 'SUSPICIOUS_LOGIN',
        `A sign-in with unusual characteristics (${anomaly.reasons.join(', ')}) is awaiting two-factor verification.`);
    }
    const challenge = createTwoFactorChallenge(user.id);
    return { requiresTwoFactor: true, challengeToken: challenge.token };
  }

  return finishLogin(user, reqMeta, anomaly);
}

/** Everything shared by direct login and successful 2FA completion. */
function finishLogin(user, reqMeta, anomaly) {
  const session = sessionService.createSession(user.id, reqMeta);
  securityService.recordLoginActivity({
    userId: user.id, email: user.email, status: anomaly.suspicious ? 'SUSPICIOUS' : 'SUCCESS',
    reason: anomaly.suspicious ? anomaly.reasons.join(', ') : null,
    sessionId: session.sessionId, ...reqMeta
  });
  securityService.audit(user.id, user.email, 'LOGIN_SUCCESS', { ip: reqMeta.ip });

  if (anomaly.suspicious) {
    securityService.createAlert(user.id, 'NEW_DEVICE_LOGIN',
      `Sign-in detected from ${reqMeta.browser} on ${reqMeta.os} (${anomaly.reasons.join(', ')}). If this wasn't you, review your active sessions.`);
    emailService.securityNotificationEmail({
      to: user.email, name: user.name, title: 'New sign-in detected',
      body: `A sign-in was detected from ${reqMeta.browser} on ${reqMeta.os}. If this wasn't you, secure your account immediately.`
    }).catch(() => {});
  }
  return { user: publicUser(findUserById(user.id)), sessionToken: session.token };
}

async function handleFailedLogin(user, email, reason, reqMeta) {
  securityService.recordLoginActivity({
    userId: user ? user.id : null, email, status: 'FAILED', reason, ...reqMeta
  });

  if (!user) {
    throw apiError(401, 'Invalid email or password.');
  }

  const attempts = user.failed_login_attempts + 1;
  db.prepare('UPDATE users SET failed_login_attempts = ?, updated_at = ? WHERE id = ?')
    .run(attempts, nowIso(), user.id);

  if (attempts === config.lockout.maxAttempts - 2) {
    securityService.createAlert(user.id, 'MULTIPLE_FAILED_LOGINS',
      'Several failed sign-in attempts were detected on your account.');
  }

  if (attempts >= config.lockout.maxAttempts) {
    const lockNumber = user.lock_count + 1;
    let minutes = config.lockout.durationMinutes;
    if (config.lockout.progressive) {
      minutes = Math.min(config.lockout.maxLockMinutes, config.lockout.durationMinutes * lockNumber);
    }
    db.prepare('UPDATE users SET locked_until = ?, lock_count = ?, updated_at = ? WHERE id = ?')
      .run(minutesFromNow(minutes), lockNumber, nowIso(), user.id);
    securityService.createAlert(user.id, 'ACCOUNT_LOCKED',
      `Your account was temporarily locked for ${minutes} minute(s) after repeated failed sign-in attempts.`);
    securityService.audit(user.id, user.email, 'ACCOUNT_LOCKED', { minutes, attempts });
    securityService.recordLoginActivity({
      userId: user.id, email, status: 'LOCKED', reason: `${attempts} failed attempts`, ...reqMeta
    });
    throw apiError(423, 'Your account has been temporarily locked due to multiple unsuccessful login attempts. Please try again later.', { code: 'ACCOUNT_LOCKED' });
  }

  const remaining = config.lockout.maxAttempts - attempts;
  throw apiError(401, `Invalid email or password. ${remaining} attempt(s) remaining before temporary lockout.`);
}

// ================================================================ two-factor auth

function createTwoFactorChallenge(userId) {
  const token = randomToken(32);
  db.prepare('INSERT INTO two_factor_challenges (user_id, token_hash, expires_at) VALUES (?, ?, ?)')
    .run(userId, sha256(token), minutesFromNow(config.tokens.twoFactorChallengeTtlMinutes));
  return { token };
}

// The challenge stays valid for retries until it succeeds or expires;
// brute force is bounded by the auth rate limiter + short challenge TTL.
function getTwoFactorChallenge(token) {
  const row = db.prepare('SELECT * FROM two_factor_challenges WHERE token_hash = ?').get(sha256(String(token || '')));
  if (!row) throw apiError(400, 'Your sign-in challenge has expired. Please sign in again.');
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    db.prepare('DELETE FROM two_factor_challenges WHERE id = ?').run(row.id);
    throw apiError(400, 'Your sign-in challenge has expired. Please sign in again.');
  }
  return row;
}

function normalizeCode(code) {
  return String(code || '').replace(/[\s-]/g, '').toUpperCase();
}

async function completeTwoFactorLogin({ challengeToken, code }, reqMeta) {
  const challenge = getTwoFactorChallenge(challengeToken);
  const user = findUserById(challenge.user_id);
  const input = normalizeCode(code);

  let ok = false;
  let method = null;
  try {
    const secret = decrypt(user.twofa_secret);
    if (/^\d{6}$/.test(input) && authenticator.verify({ token: input, secret })) {
      ok = true;
      method = 'totp';
    }
  } catch { /* fall through to recovery codes */ }

  if (!ok && /^[A-Z0-9]{8}$/.test(input)) {
    const row = db.prepare(
      'SELECT * FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL'
    ).get(user.id, sha256(input));
    if (row) {
      db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ?').run(nowIso(), row.id);
      ok = true;
      method = 'recovery-code';
    }
  }

  if (!ok) {
    securityService.recordLoginActivity({
      userId: user.id, email: user.email, status: 'FAILED', reason: 'invalid 2FA code', ...reqMeta
    });
    throw apiError(401, 'Invalid two-factor code. Use your authenticator code or a recovery code.');
  }

  // One-time use: consume the challenge only after a successful verification.
  db.prepare('DELETE FROM two_factor_challenges WHERE id = ?').run(challenge.id);
  securityService.audit(user.id, user.email, 'LOGIN_2FA_SUCCESS', { method });
  const anomaly = securityService.analyzeLoginAnomaly(user.id, reqMeta);
  return finishLogin(user, reqMeta, anomaly);
}

async function setupTwoFactor(userId, { force = false } = {}) {
  const user = findUserById(userId);
  if (user.twofa_enabled) {
    throw apiError(400, 'Two-factor authentication is already enabled on your account.');
  }
  // Reuse a pending secret so re-clicking “Set up” never invalidates a QR code
  // the user has already scanned — unless a brand-new key is requested.
  let secret;
  if (user.twofa_secret && !force) {
    secret = decrypt(user.twofa_secret);
  } else {
    secret = authenticator.generateSecret();
    db.prepare('UPDATE users SET twofa_secret = ?, updated_at = ? WHERE id = ?')
      .run(encrypt(secret), nowIso(), userId);
  }
  const otpauthUrl = authenticator.keyuri(
    `${user.name} (${user.email})`, config.totp.issuer, secret
  );
  const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl, { margin: 2, width: 300, errorCorrectionLevel: 'M' });
  return { secret, otpauthUrl, qrCodeDataUrl };
}

function generateRecoveryCodes(userId) {
  db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
  const codes = [];
  for (let i = 0; i < 10; i += 1) {
    codes.push(randomToken(6).toUpperCase().replace(/[^A-Z0-9]/g, 'X'));
  }
  const insert = db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');
  for (const code of codes) insert.run(userId, sha256(code));
  return codes;
}

async function enableTwoFactor(userId, code) {
  const user = findUserById(userId);
  if (!user.twofa_secret) throw apiError(400, 'Please start 2FA setup first.');
  const secret = decrypt(user.twofa_secret);
  if (!authenticator.verify({ token: normalizeCode(code), secret })) {
    // Diagnose the failure: a wide ±20-minute probe separates clock skew from
    // a mismatched key (e.g. an entry added during an older setup attempt).
    const skewProbe = authenticator.clone({ window: 40 });
    if (skewProbe.verify({ token: normalizeCode(code), secret })) {
      throw apiError(400, 'Your code matches but your phone\'s clock is off by more than 2 minutes. Set your phone\'s date & time to “Automatic”, wait a few seconds, then try again.');
    }
    throw apiError(400, 'The key stored in your authenticator app doesn\'t match this screen — it was added during an older setup. In your app, delete the existing “SecureApp” entry, then click “Start over with a new key” below and scan the fresh QR code.');
  }
  db.prepare('UPDATE users SET twofa_enabled = 1, updated_at = ? WHERE id = ?').run(nowIso(), userId);
  const recoveryCodes = generateRecoveryCodes(userId);
  securityService.createAlert(userId, 'TWO_FACTOR_ENABLED', 'Two-factor authentication is now protecting your account.');
  securityService.audit(userId, user.email, 'TWO_FACTOR_ENABLED', null);
  return { recoveryCodes };
}

async function disableTwoFactor(userId, { password, code }) {
  const user = findUserById(userId);
  const passwordOk = await bcrypt.compare(String(password || ''), user.password_hash);
  if (!passwordOk) throw apiError(401, 'Your current password is incorrect.');

  if (user.twofa_secret) {
    const secret = decrypt(user.twofa_secret);
    const input = normalizeCode(code);
    const totpOk = /^\d{6}$/.test(input) && authenticator.verify({ token: input, secret });
    let recoveryOk = false;
    if (!totpOk && /^[A-Z0-9]{8}$/.test(input)) {
      const row = db.prepare('SELECT * FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
        .get(userId, sha256(input));
      if (row) {
        db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ?').run(nowIso(), row.id);
        recoveryOk = true;
      }
    }
    if (!totpOk && !recoveryOk) {
      throw apiError(400, 'Provide a valid authenticator or recovery code to disable 2FA.');
    }
  }

  db.prepare('UPDATE users SET twofa_enabled = 0, twofa_secret = NULL, updated_at = ? WHERE id = ?')
    .run(nowIso(), userId);
  db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
  securityService.createAlert(userId, 'TWO_FACTOR_DISABLED', 'Two-factor authentication was turned off.');
  securityService.audit(userId, user.email, 'TWO_FACTOR_DISABLED', null);
}

// ================================================================ password reset

async function requestPasswordReset(email) {
  const cleanEmail = String(email || '').trim().toLowerCase();
  const generic = { message: 'If an account exists with this email, a reset link has been sent.' };
  const user = findUserByEmail(cleanEmail);
  if (!user) return generic;

  db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL').run(user.id);
  const token = randomToken(32);
  db.prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)')
    .run(user.id, sha256(token), minutesFromNow(config.tokens.passwordResetTtlMinutes));

  const url = `${config.appUrl}/reset-password?token=${token}`;
  try {
    await emailService.passwordResetEmail({ to: user.email, name: user.name, url });
  } catch { /* generic response regardless */ }

  securityService.createAlert(user.id, 'PASSWORD_RESET_REQUESTED', 'A password reset was requested for your account.');
  securityService.audit(user.id, user.email, 'PASSWORD_RESET_REQUESTED', null);
  return !config.smtp.host && !config.isProduction ? { ...generic, devEmailUrl: url } : generic;
}

function validateResetToken(token) {
  const row = db.prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ?').get(sha256(String(token || '')));
  if (!row) throw apiError(400, 'This reset link is invalid. Please request a new one.');
  if (row.used_at) throw apiError(400, 'This reset link has already been used. Please request a new one.');
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    throw apiError(400, 'This reset link has expired. Please request a new one.', { expired: true });
  }
  return row;
}

async function resetPassword(token, newPassword) {
  const row = validateResetToken(token);
  const user = findUserById(row.user_id);

  const policy = validatePassword(newPassword, { email: user.email, name: user.name });
  if (!policy.valid) throw apiError(400, policy.errors.join(' '), { errors: policy.errors });
  if (await passwordWasUsedRecently(user.id, newPassword)) {
    throw apiError(400, `You cannot reuse one of your last ${config.password.historyCount} passwords.`);
  }

  const passwordHash = await bcrypt.hash(newPassword, config.password.bcryptRounds);
  db.prepare('UPDATE password_reset_tokens SET used_at = ? WHERE id = ?').run(nowIso(), row.id);
  db.prepare(
    `UPDATE users SET password_hash = ?, password_changed_at = ?, failed_login_attempts = 0,
     locked_until = NULL, updated_at = ? WHERE id = ?`
  ).run(passwordHash, nowIso(), nowIso(), user.id);
  pushPasswordHistory(user.id, passwordHash);

  const revoked = sessionService.revokeAllSessions(user.id, 'revoked');
  securityService.createAlert(user.id, 'PASSWORD_RESET_COMPLETED',
    `Your password was reset and ${revoked} active session(s) were signed out.`);
  securityService.audit(user.id, user.email, 'PASSWORD_RESET_COMPLETED', { sessionsRevoked: revoked });
  emailService.securityNotificationEmail({
    to: user.email, name: user.name, title: 'Password changed',
    body: 'Your password was just reset and all active sessions were signed out. If this wasn\'t you, contact support immediately.'
  }).catch(() => {});

  return { message: 'Your password has been reset. Please sign in with your new password.' };
}

// ================================================================ change password

async function changePassword(userId, { currentPassword, newPassword }) {
  const user = findUserById(userId);
  const currentOk = await bcrypt.compare(String(currentPassword || ''), user.password_hash);
  if (!currentOk) throw apiError(401, 'Your current password is incorrect.');

  const policy = validatePassword(newPassword, { email: user.email, name: user.name });
  if (!policy.valid) throw apiError(400, policy.errors.join(' '), { errors: policy.errors });

  if (await passwordWasUsedRecently(userId, newPassword)) {
    throw apiError(400, `You cannot reuse one of your last ${config.password.historyCount} passwords, including your current one.`);
  }

  const passwordHash = await bcrypt.hash(newPassword, config.password.bcryptRounds);
  db.prepare('UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?')
    .run(passwordHash, nowIso(), nowIso(), userId);
  pushPasswordHistory(userId, passwordHash);

  const revoked = sessionService.revokeAllSessions(userId, 'revoked');
  securityService.createAlert(userId, 'PASSWORD_CHANGED',
    `Your password was changed and ${revoked} active session(s) were signed out.`);
  securityService.audit(userId, user.email, 'PASSWORD_CHANGED', { sessionsRevoked: revoked });
  emailService.securityNotificationEmail({
    to: user.email, name: user.name, title: 'Password changed',
    body: 'Your password was just changed and all active sessions were signed out. If this wasn\'t you, reset your password immediately.'
  }).catch(() => {});

  return { message: 'Password updated. All sessions were signed out — please sign in again.' };
}

// ================================================================ history

function pushPasswordHistory(userId, passwordHash) {
  db.prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)').run(userId, passwordHash);
  const rows = db.prepare(
    'SELECT id FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT -1 OFFSET ?'
  ).all(userId, config.password.historyCount);
  if (rows.length > 0) {
    db.prepare(`DELETE FROM password_history WHERE id IN (${rows.map((r) => r.id).join(',')})`).run();
  }
}

async function passwordWasUsedRecently(userId, password) {
  const rows = db.prepare(
    'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?'
  ).all(userId, config.password.historyCount);
  for (const row of rows) {
    // eslint-disable-next-line no-await-in-loop
    if (await bcrypt.compare(password, row.password_hash)) return true;
  }
  return false;
}

// ================================================================ errors

function apiError(status, message, data = {}) {
  const err = new Error(message);
  err.status = status;
  err.data = data;
  return err;
}

module.exports = {
  findUserByEmail,
  findUserById,
  publicUser,
  register,
  verifyEmail,
  resendVerification,
  issueEmailVerification,
  login,
  completeTwoFactorLogin,
  setupTwoFactor,
  enableTwoFactor,
  disableTwoFactor,
  generateRecoveryCodes,
  requestPasswordReset,
  resetPassword,
  changePassword,
  apiError,
  EMAIL_NOT_VERIFIED,
  TWO_FACTOR_REQUIRED
};
