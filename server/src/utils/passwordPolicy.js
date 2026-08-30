'use strict';

/**
 * Reusable password policy engine (shared by registration, change and reset).
 * Produces both pass/fail results with reasons and a strength score for the UI.
 */

const config = require('../config');

// Extremely common passwords that are always rejected (subset of breach lists).
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'passw0rd', '123456', '12345678', '123456789',
  '1234567890', 'qwerty', 'qwerty123', 'abc123', 'letmein', 'welcome', 'welcome1',
  'iloveyou', 'admin', 'admin123', 'root', 'toor', 'monkey', 'dragon', 'master',
  'sunshine', 'princess', 'football', 'baseball', 'superman', 'batman', 'trustno1',
  'hello123', 'shadow', 'michael', 'jennifer', 'jordan23', 'harley', 'ranger',
  'hunter2', 'changeme', 'secret', 'p@ssw0rd', 'p@ssword', 'pass123', 'test123',
  'user123', 'login123', 'qazwsx', '1q2w3e4r', '1qaz2wsx', 'zxcvbnm', 'asdfghjkl'
]);

const RULES = [
  {
    key: 'length',
    test: (pw) => pw.length >= config.password.minLength && pw.length <= config.password.maxLength,
    label: `At least ${config.password.minLength} characters`
  },
  { key: 'upper', test: (pw) => /[A-Z]/.test(pw), label: 'One uppercase letter (A–Z)' },
  { key: 'lower', test: (pw) => /[a-z]/.test(pw), label: 'One lowercase letter (a–z)' },
  { key: 'number', test: (pw) => /[0-9]/.test(pw), label: 'One number (0–9)' },
  {
    key: 'special',
    test: (pw) => /[^A-Za-z0-9\s]/.test(pw),
    label: 'One special character (!@#$%…)'
  }
];

/**
 * Validate a password against the policy.
 * @param {string} password
 * @param {{email?: string, name?: string}} context used to reject identity-derived passwords
 * @returns {{valid: boolean, errors: string[], rules: object[]}}
 */
function validatePassword(password, context = {}) {
  const errors = [];
  const ruleResults = RULES.map((rule) => ({ key: rule.key, label: rule.label, met: rule.test(password) }));

  for (const rule of ruleResults) {
    if (!rule.met) errors.push(rule.label);
  }

  const lower = String(password).toLowerCase();
  // Normalize identically to scorePassword (strip ALL non-alphanumerics)
  // so common-password detection cannot produce false positives from emails.
  if (COMMON_PASSWORDS.has(lower.replace(/[^a-z0-9]/g, ''))) {
    errors.push('This password is too common and not allowed.');
  }

  const identifiers = [context.email, context.name]
    .filter(Boolean)
    .map((v) => String(v).toLowerCase().split('@')[0].trim())
    .filter((v) => v.length >= 3);

  for (const identifier of identifiers) {
    if (lower.includes(identifier)) {
      errors.push('Password must not contain your name or email address.');
      break;
    }
  }

  return { valid: errors.length === 0, errors, rules: ruleResults };
}

/**
 * Strength score 0–4 → weak / fair / good / strong.
 * Never receives/stores the real password beyond this request.
 */
function scorePassword(password) {
  if (!password) return { score: 0, label: 'none' };
  let points = 0;
  if (password.length >= 8) points += 1;
  if (password.length >= 12) points += 1;
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((rx) => rx.test(password)).length;
  points += classes >= 3 ? 1 : 0;
  points += classes === 4 ? 1 : 0;
  if (COMMON_PASSWORDS.has(password.toLowerCase().replace(/[^a-z0-9]/g, ''))) points = Math.min(points, 1);

  const labels = ['weak', 'weak', 'fair', 'good', 'strong'];
  const capped = Math.max(0, Math.min(4, points));
  return { score: capped, label: labels[capped] };
}

module.exports = { validatePassword, scorePassword, RULES };
