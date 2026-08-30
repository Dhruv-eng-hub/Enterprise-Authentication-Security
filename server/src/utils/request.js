'use strict';

/**
 * Request fingerprinting helpers: user-agent parsing, client IP extraction
 * and a small validator collection. Nothing here stores sensitive data.
 */

const { UAParser } = require('ua-parser-js');

/** Parse a User-Agent header into device / browser / OS labels. */
function parseUserAgent(uaHeader = '') {
  const ua = new UAParser(uaHeader || '').getResult();
  const browser = ua.browser && ua.browser.name ? ua.browser.name : 'Unknown Browser';
  const os = ua.os && ua.os.name ? ua.os.name : 'Unknown OS';
  const deviceType =
    ua.device && ua.device.type
      ? ua.device.type.charAt(0).toUpperCase() + ua.device.type.slice(1)
      : 'Desktop';
  return { browser, os, device: deviceType };
}

/** Best-effort client IP (honors a single trusted proxy hop). */
function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : 'unknown';
}

/** Mask an IP for display in alerts ("103.xx.xx.21") — avoids leaking full IPs in notifications. */
function maskIp(ip) {
  if (!ip || ip === 'unknown') return 'unknown';
  const parts = String(ip).split('.');
  if (parts.length === 4) return `${parts[0]}.xx.xx.${parts[3]}`;
  return String(ip).slice(0, 4) + '…';
}

const EMAIL_RX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function isEmail(value) {
  return typeof value === 'string' && EMAIL_RX.test(value.trim()) && value.length <= 254;
}

/** Basic input sanitization: trim + strip control chars + length cap. */
function sanitizeText(value, maxLength = 200) {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, maxLength);
}

module.exports = { parseUserAgent, clientIp, maskIp, isEmail, sanitizeText };
