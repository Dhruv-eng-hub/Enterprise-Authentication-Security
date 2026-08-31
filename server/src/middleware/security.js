'use strict';

/**
 * Security middleware:
 *  - requireAuth: resolves the HttpOnly session cookie to a DB session
 *  - requireVerified / requireAdmin: authorization gates
 *  - security headers, CORS and cookie helpers
 *  - rate limiters for sensitive endpoints
 */

const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const sessionService = require('../services/sessionService');
const authService = require('../services/authService');

function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    path: '/',
    maxAge: config.session.maxLifetimeHours * 3_600_000
  };
}

function securityHeaders(app) {
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });
}

/** True when the origin is an allowed frontend (or any localhost port in dev,
 *  since Vite silently picks the next free port when the default is busy). */
function allowedOrigin(origin) {
  if (!origin) return true;
  if (config.clientOrigins.includes(origin)) return true;
  if (origin === `http://localhost:${config.port}`) return true;
  if (!config.isProduction && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;
  return false;
}

function corsMiddleware(app) {
  app.use(cors({
    origin: (origin, cb) => cb(null, allowedOrigin(origin) ? (origin || config.clientOrigin) : false),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type']
  }));
}

/** Resolve the session cookie → req.session / req.user, or 401. */
function requireAuth(req, res, next) {
  const token = req.cookies ? req.cookies[config.session.cookieName] : null;
  const session = sessionService.findByToken(token);
  if (!session) {
    return res.status(401).json({ message: 'You are not signed in. Please sign in again.' });
  }
  const user = authService.findUserById(session.user_id);
  if (!user) {
    return res.status(401).json({ message: 'You are not signed in. Please sign in again.' });
  }
  req.session = session;
  req.user = user;
  return next();
}

/** Sensitive routes additionally require a verified email. */
function requireVerified(req, res, next) {
  if (!req.user.email_verified) {
    return res.status(403).json({
      message: 'Please verify your email address to continue.',
      code: 'EMAIL_NOT_VERIFIED'
    });
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Administrator access required.' });
  }
  return next();
}

/** CSRF hardening for state-changing requests: require an allowed origin. */
function sameOriginForMutations(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!allowedOrigin(req.headers.origin)) {
    return res.status(403).json({ message: 'Cross-origin request rejected.' });
  }
  return next();
}

const windowMs = config.rateLimit.windowMinutes * 60_000;

const limiterOptions = (max, message) => ({
  windowMs,
  limit: max,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message }
});

const generalLimiter = rateLimit(limiterOptions(
  config.rateLimit.general,
  'Too many requests. Please slow down.'
));

const authLimiter = rateLimit(limiterOptions(
  config.rateLimit.auth,
  'Too many authentication attempts. Please try again later.'
));

const resendLimiter = rateLimit(limiterOptions(
  config.rateLimit.resend,
  'Too many verification emails requested. Please try again later.'
));

const forgotLimiter = rateLimit(limiterOptions(
  config.rateLimit.forgot,
  'Too many password reset requests. Please try again later.'
));

module.exports = {
  sessionCookieOptions,
  securityHeaders,
  corsMiddleware,
  requireAuth,
  requireVerified,
  requireAdmin,
  sameOriginForMutations,
  generalLimiter,
  authLimiter,
  resendLimiter,
  forgotLimiter
};
