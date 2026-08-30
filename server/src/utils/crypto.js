'use strict';

/**
 * Cryptographic helpers. All randomness comes from Node's CSPRNG;
 * one-time tokens are only ever persisted as SHA-256 hashes;
 * 2FA secrets are encrypted at rest with AES-256-GCM.
 */

const crypto = require('crypto');
const config = require('../config');

/** Cryptographically secure URL-safe random token. */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** SHA-256 hex digest — used to hash one-time tokens before storage. */
function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function deriveKey() {
  return crypto.createHash('sha256').update(config.serverSecret).digest();
}

/** AES-256-GCM encryption for sensitive values at rest (e.g. TOTP secrets). */
function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('base64'), tag.toString('base64'), encrypted.toString('base64')].join('.');
}

function decrypt(payload) {
  const [ivB64, tagB64, dataB64] = String(payload).split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
}

/** Timing-safe string comparison. */
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function nowIso() {
  return new Date().toISOString();
}

function minutesFromNow(minutes) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function hoursFromNow(hours) {
  return new Date(Date.now() + hours * 3_600_000).toISOString();
}

module.exports = {
  randomToken,
  sha256,
  encrypt,
  decrypt,
  safeEqual,
  nowIso,
  minutesFromNow,
  hoursFromNow
};
