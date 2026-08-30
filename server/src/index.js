'use strict';

/**
 * Enterprise Authentication & Security — API server entry point.
 * Express + SQLite. All secrets come from server/.env.
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');

const config = require('./config');
const db = require('./db'); // initializes schema on require
const logger = require('./utils/logger');
const { nowIso } = require('./utils/crypto');
const { validatePassword } = require('./utils/passwordPolicy');

const mw = require('./middleware/security');
const { errorHandler, notFound } = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth');
const securityRoutes = require('./routes/security');
const adminRoutes = require('./routes/admin');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

// ---------------------------------------------------------------- middleware
mw.securityHeaders(app);
mw.corsMiddleware(app);
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(mw.sameOriginForMutations);

// Lightweight request logging — method/path/status only, never bodies or headers.
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.info(`${req.method} ${req.originalUrl} → ${res.statusCode} (${Date.now() - start}ms)`);
  });
  next();
});

app.use(mw.generalLimiter);

// ---------------------------------------------------------------- routes
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
// Route modules apply their own rate limiters (auth/resend/forgot windows).
app.use('/api/auth', authRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/admin', adminRoutes);

app.use(notFound);
app.use(errorHandler);

// ---------------------------------------------------------------- admin seeding
function seedAdmin() {
  if (!config.admin.email || !config.admin.password) {
    logger.warn('ADMIN_EMAIL / ADMIN_PASSWORD not set — no administrator account will be seeded.');
    return;
  }
  const email = config.admin.email.trim().toLowerCase();
  const existing = db.prepare('SELECT id, role FROM users WHERE email = ?').get(email);
  if (existing) return;

  const policy = validatePassword(config.admin.password, { email });
  if (!policy.valid) {
    logger.warn(`ADMIN_PASSWORD does not satisfy the password policy (${policy.errors.join('; ')}) — admin not seeded.`);
    return;
  }

  const now = nowIso();
  const hash = bcrypt.hashSync(config.admin.password, config.password.bcryptRounds);
  db.prepare(
    `INSERT INTO users (name, email, password_hash, role, email_verified, email_verified_at, password_changed_at, created_at, updated_at)
     VALUES (?, ?, ?, 'admin', 1, ?, ?, ?, ?)`
  ).run(config.admin.name, email, hash, now, now, now, now);
  logger.info(`Administrator account seeded: ${email}`);
}

seedAdmin();

app.listen(config.port, () => {
  logger.info(`Security API listening on http://localhost:${config.port} (${config.env})`);
  if (!config.smtp.host) {
    logger.info('SMTP not configured — transactional emails are printed to this console, and action links are returned by the API in development mode.');
  }
});
