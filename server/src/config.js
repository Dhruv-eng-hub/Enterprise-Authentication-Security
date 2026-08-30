'use strict';

/**
 * Centralized, environment-driven configuration for all security policies.
 * Every policy value is configurable through server/.env (see .env.example).
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const int = (value, fallback) => {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const bool = (value, fallback) => {
  if (value === undefined || value === null || value === '') return fallback;
  return String(value).toLowerCase() === 'true';
};

const isProduction = process.env.NODE_ENV === 'production';

const config = {
  env: process.env.NODE_ENV || 'development',
  isProduction,
  port: int(process.env.PORT, 5000),
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  // Comma-separated list of allowed frontend origins (Vite may pick a new port
  // like 5174 when the default is busy).
  clientOrigins: (process.env.CLIENT_ORIGIN || 'http://localhost:5173')
    .split(',').map((o) => o.trim()).filter(Boolean),
  appUrl: process.env.APP_URL || process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  dbFile: process.env.DB_FILE || './data/app.db',

  serverSecret: process.env.SERVER_SECRET || '',

  session: {
    inactivityMinutes: int(process.env.SESSION_INACTIVITY_MINUTES, 30),
    maxLifetimeHours: int(process.env.SESSION_MAX_LIFETIME_HOURS, 12),
    singleSession: bool(process.env.SINGLE_SESSION, true),
    cookieName: 'sid',
    twoFactorCookieName: 'tfa_challenge'
  },

  lockout: {
    maxAttempts: int(process.env.LOCK_MAX_ATTEMPTS, 5),
    durationMinutes: int(process.env.LOCK_DURATION_MINUTES, 15),
    // Progressive lockout multiplies the duration with every repeated lock,
    // capped at 24 hours, so attackers cannot hammer an account indefinitely
    // while legitimate users are never permanently locked out.
    progressive: true,
    maxLockMinutes: 24 * 60
  },

  password: {
    minLength: int(process.env.PASSWORD_MIN_LENGTH, 8),
    maxLength: int(process.env.PASSWORD_MAX_LENGTH, 128),
    historyCount: int(process.env.PASSWORD_HISTORY_COUNT, 5),
    maxAgeDays: int(process.env.PASSWORD_MAX_AGE_DAYS, 90),
    bcryptRounds: 12
  },

  tokens: {
    emailVerificationTtlMinutes: int(process.env.EMAIL_VERIFICATION_TOKEN_TTL_MINUTES, 60),
    passwordResetTtlMinutes: int(process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES, 30),
    twoFactorChallengeTtlMinutes: 5
  },

  rateLimit: {
    windowMinutes: int(process.env.RATE_LIMIT_WINDOW_MINUTES, 15),
    general: int(process.env.RATE_LIMIT_GENERAL, 300),
    auth: int(process.env.RATE_LIMIT_AUTH, 20),
    resend: int(process.env.RATE_LIMIT_RESEND, 3),
    forgot: int(process.env.RATE_LIMIT_FORGOT, 5)
  },

  admin: {
    email: process.env.ADMIN_EMAIL || '',
    name: process.env.ADMIN_NAME || 'System Administrator',
    password: process.env.ADMIN_PASSWORD || ''
  },

  smtp: {
    host: process.env.SMTP_HOST || '',
    port: int(process.env.SMTP_PORT, 587),
    secure: bool(process.env.SMTP_SECURE, false),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.MAIL_FROM || 'SecureApp <no-reply@example.com>'
  },

  totp: {
    issuer: process.env.TOTP_ISSUER || 'SecureApp',
    // Number of 30-second time-steps accepted before/after the current one.
    // 4 ≈ ±2 minutes, tolerant of slightly skewed phone clocks in development.
    window: int(process.env.TOTP_WINDOW, 4)
  }
};

if (!config.serverSecret || config.serverSecret.startsWith('change-me')) {
  // Fail fast in production; warn in development.
  if (config.isProduction) {
    throw new Error('SERVER_SECRET must be set to a strong random value in production.');
  }
  console.warn('[security] WARNING: SERVER_SECRET is not set. Using an insecure development fallback.');
  config.serverSecret = 'dev-insecure-fallback-secret-do-not-use-in-prod-000';
}

module.exports = config;
