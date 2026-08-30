'use strict';

/**
 * Email delivery service.
 * - With SMTP_HOST configured: real emails via nodemailer.
 * - Without SMTP: emails are rendered to the server console, and in
 *   development the action URLs are returned to the API caller so every
 *   flow remains fully testable without a mail provider.
 */

const nodemailer = require('nodemailer');
const config = require('../config');
const logger = require('../utils/logger');

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (config.smtp.host) {
    transporter = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined
    });
  } else {
    // jsonTransport renders the message instead of sending — used for local dev only.
    transporter = nodemailer.createTransport({ jsonTransport: true });
  }
  return transporter;
}

async function sendEmail({ to, subject, html, text }) {
  try {
    const info = await getTransporter().sendMail({ from: config.smtp.from, to, subject, html, text });
    if (!config.smtp.host) {
      logger.info(`[email-dev] Email to ${to} — "${subject}" (no SMTP configured, console mode)`);
    }
    return info;
  } catch (err) {
    logger.error(`Email delivery failed for ${to}: ${err.message}`);
    throw err;
  }
}

function verificationEmail({ to, name, url }) {
  return sendEmail({
    to,
    subject: 'Verify your email address',
    text: `Hi ${name},\n\nPlease verify your email by opening this link (valid for ${config.tokens.emailVerificationTtlMinutes} minutes):\n${url}\n\nIf you did not create an account, you can ignore this email.`,
    html: `
      <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px">
        <h2 style="color:#1e293b">Verify your email</h2>
        <p>Hi ${name},</p>
        <p>Click the button below to verify your email address and activate your account. The link expires in ${config.tokens.emailVerificationTtlMinutes} minutes.</p>
        <p style="margin:24px 0"><a href="${url}" style="background:#2563eb;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Verify Email</a></p>
        <p style="color:#64748b;font-size:13px">If you did not create an account, you can safely ignore this email.</p>
      </div>`
  });
}

function passwordResetEmail({ to, name, url }) {
  return sendEmail({
    to,
    subject: 'Reset your password',
    text: `Hi ${name},\n\nReset your password using this link (valid for ${config.tokens.passwordResetTtlMinutes} minutes):\n${url}\n\nIf you did not request a reset, ignore this email and consider securing your account.`,
    html: `
      <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px">
        <h2 style="color:#1e293b">Password reset request</h2>
        <p>Hi ${name},</p>
        <p>We received a request to reset your password. The link below expires in ${config.tokens.passwordResetTtlMinutes} minutes.</p>
        <p style="margin:24px 0"><a href="${url}" style="background:#dc2626;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Reset Password</a></p>
        <p style="color:#64748b;font-size:13px">If you did not request this, ignore this email. Your password will not change.</p>
      </div>`
  });
}

function securityNotificationEmail({ to, name, title, body }) {
  return sendEmail({
    to,
    subject: `Security notice: ${title}`,
    text: `Hi ${name},\n\n${title}\n\n${body}\n\nIf this was not you, sign in and review your security dashboard immediately.`,
    html: `
      <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px">
        <h2 style="color:#b45309">🔐 ${title}</h2>
        <p>Hi ${name},</p>
        <p>${body}</p>
        <p style="color:#64748b;font-size:13px">If this was not you, sign in and secure your account immediately.</p>
      </div>`
  });
}

module.exports = { verificationEmail, passwordResetEmail, securityNotificationEmail };
