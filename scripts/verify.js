'use strict';

/**
 * End-to-end verification of every security flow against the running API.
 * Usage: node scripts/verify.js  (server must be running on :5000)
 */

const BASE = 'http://localhost:5000/api';

let passed = 0;
let failed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    failures.push(name);
    console.log(`  FAIL  ${name} ${detail}`);
  }
}

function jar() {
  const store = {};
  return {
    header() { return Object.entries(store).map(([k, v]) => `${k}=${v}`).join('; '); },
    absorb(res) {
      const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
      for (const c of setCookies) {
        const [pair] = c.split(';');
        const idx = pair.indexOf('=');
        store[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
      }
    }
  };
}

async function call(method, path, { body, cookies } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (cookies) headers.Cookie = cookies.header();
  const res = await fetch(BASE + path, {
    method, headers, redirect: 'manual',
    body: body ? JSON.stringify(body) : undefined
  });
  if (cookies) cookies.absorb(res);
  let data = null;
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('json')) data = await res.json();
  else data = await res.text();
  return { status: res.status, data, headers: res.headers };
}

function extractToken(url) {
  const m = String(url).match(/token=([A-Za-z0-9_-]+)/);
  return m ? m[1] : null;
}

(async () => {
  const email = `user.${Date.now()}@example.com`;
  const strongPw = 'V3ryStr0ng!Passw0rd';
  const userCookies = jar();

  console.log('\n== 1. Health ==');
  const health = await call('GET', '/health');
  check('health endpoint', health.status === 200 && health.data.status === 'ok');

  console.log('\n== 2. Registration & password policy ==');
  const weak = await call('POST', '/auth/register', { body: { name: 'Test User', email, password: 'weak' } });
  check('weak password rejected', weak.status === 400);
  const common = await call('POST', '/auth/register', { body: { name: 'Test User', email, password: 'Password123!' } });
  check('common password rejected', common.status === 400);
  const identity = await call('POST', '/auth/register', { body: { name: 'Test User', email, password: `${email.split('@')[0]}!9Ab` } });
  check('email-derived password rejected', identity.status === 400);
  const reg = await call('POST', '/auth/register', { body: { name: 'Test User', email, password: strongPw } });
  check('valid registration succeeds', reg.status === 201, JSON.stringify(reg.data));
  check('verification link returned in dev', Boolean(reg.data.devEmailUrl));
  const dup = await call('POST', '/auth/register', { body: { name: 'Test User', email, password: strongPw } });
  check('duplicate email rejected', dup.status === 409);

  console.log('\n== 3. Login blocked before verification ==');
  const unverifiedLogin = await call('POST', '/auth/login', { body: { email, password: strongPw } });
  check('unverified login blocked', unverifiedLogin.status === 403 && unverifiedLogin.data.code === 'EMAIL_NOT_VERIFIED');

  console.log('\n== 4. Email verification ==');
  const token = extractToken(reg.data.devEmailUrl);
  const verify = await call('POST', '/auth/verify-email', { body: { token } });
  check('email verification succeeds', verify.status === 200);
  const reuse = await call('POST', '/auth/verify-email', { body: { token } });
  check('verification token cannot be reused', reuse.status === 400);
  const badToken = await call('POST', '/auth/verify-email', { body: { token: 'invalid-token' } });
  check('invalid token handled', badToken.status === 400);

  console.log('\n== 5. Resend verification (rate limited, generic response) ==');
  const resend1 = await call('POST', '/auth/resend-verification', { body: { email } });
  check('resend returns generic message', resend1.status === 200 && /If an account exists/.test(resend1.data.message));
  const resendUnknown = await call('POST', '/auth/resend-verification', { body: { email: 'ghost@example.com' } });
  check('unknown email gets same response', resendUnknown.status === 200 && resendUnknown.data.message === resend1.data.message);

  console.log('\n== 6. Login, session & security center ==');
  const badLogin = await call('POST', '/auth/login', { body: { email, password: 'WrongPass!1' } });
  check('wrong password rejected', badLogin.status === 401);
  const login = await call('POST', '/auth/login', { body: { email, password: strongPw }, cookies: userCookies });
  check('login succeeds after verification', login.status === 200 && login.data.user.email === email);
  const me = await call('GET', '/auth/me', { cookies: userCookies });
  check('authenticated /me works', me.status === 200 && me.data.user.email === email);
  const meNoAuth = await call('GET', '/auth/me');
  check('unauthenticated /me rejected', meNoAuth.status === 401);

  const overview = await call('GET', '/security/overview', { cookies: userCookies });
  check('security overview + score', overview.status === 200 && typeof overview.data.score.value === 'number');
  check('recommendations present', Array.isArray(overview.data.recommendations));

  const sessions = await call('GET', '/security/sessions', { cookies: userCookies });
  check('sessions listed', sessions.status === 200 && sessions.data.sessions.length >= 1);
  const current = sessions.data.sessions.find((s) => s.is_current);
  check('current session identified', Boolean(current));

  const activity = await call('GET', '/security/login-activity?page=1&limit=5', { cookies: userCookies });
  check('login activity paginated', activity.status === 200 && activity.data.total >= 3);
  const csv = await call('GET', '/security/login-activity/export', { cookies: userCookies });
  check('CSV export works', csv.status === 200 && String(csv.data).startsWith('Timestamp,'));

  const alerts = await call('GET', '/security/alerts', { cookies: userCookies });
  check('alerts listed', alerts.status === 200);
  if (alerts.data.alerts.length > 0) {
    const read = await call('PATCH', `/security/alerts/${alerts.data.alerts[0].id}/read`, { cookies: userCookies });
    check('alert marked read', read.status === 200);
  }
  const readAll = await call('PATCH', '/security/alerts/read-all', { cookies: userCookies });
  check('mark all alerts read', readAll.status === 200);

  const timeline = await call('GET', '/security/timeline', { cookies: userCookies });
  check('security timeline', timeline.status === 200 && timeline.data.events.length > 0);

  console.log('\n== 7. Password change & history ==');
  const changeBad = await call('POST', '/auth/change-password', { body: { currentPassword: 'nope', newPassword: 'N3wPass!word9' }, cookies: userCookies });
  check('wrong current password rejected', changeBad.status === 401);
  const reuseOld = await call('POST', '/auth/change-password', { body: { currentPassword: strongPw, newPassword: strongPw }, cookies: userCookies });
  check('password reuse blocked', reuseOld.status === 400);
  const newPw = 'An0ther!Great99Pass';
  const change = await call('POST', '/auth/change-password', { body: { currentPassword: strongPw, newPassword: newPw }, cookies: userCookies });
  check('password change succeeds', change.status === 200);
  const meAfterChange = await call('GET', '/auth/me', { cookies: userCookies });
  check('session revoked after password change', meAfterChange.status === 401);
  const reLogin = await call('POST', '/auth/login', { body: { email, password: newPw }, cookies: userCookies });
  check('re-login with new password', reLogin.status === 200);

  console.log('\n== 8. Password reset flow ==');
  const forgot = await call('POST', '/auth/forgot-password', { body: { email } });
  check('forgot-password generic response', forgot.status === 200 && /If an account exists/.test(forgot.data.message));
  const forgotUnknown = await call('POST', '/auth/forgot-password', { body: { email: 'ghost@example.com' } });
  check('account existence not leaked', forgotUnknown.data.message === forgot.data.message);
  const resetToken = extractToken(forgot.data.devEmailUrl);
  check('reset link returned in dev', Boolean(resetToken));
  const finalPw = 'F1nal!Secure#Pass';
  const reset = await call('POST', '/auth/reset-password', { body: { token: resetToken, password: finalPw } });
  check('password reset succeeds', reset.status === 200);
  const resetReuse = await call('POST', '/auth/reset-password', { body: { token: resetToken, password: 'Xy9!mKqL2pZr' } });
  check('reset token single-use', resetReuse.status === 400);
  const loginAfterReset = await call('POST', '/auth/login', { body: { email, password: finalPw }, cookies: userCookies });
  check('login with reset password', loginAfterReset.status === 200);

  console.log('\n== 9. Account lockout ==');
  const lockEmail = `lock.${Date.now()}@example.com`;
  await call('POST', '/auth/register', { body: { name: 'Lock Test', email: lockEmail, password: strongPw } });
  const regLock = await call('POST', '/auth/register', { body: { name: 'X Y', email: `x.${Date.now()}@e.com`, password: strongPw } });
  void regLock;
  for (let i = 0; i < 5; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await call('POST', '/auth/login', { body: { email: lockEmail, password: 'Wrong!Pass1' } });
  }
  const locked = await call('POST', '/auth/login', { body: { email: lockEmail, password: strongPw } });
  check('account locked after 5 failures', locked.status === 423 && locked.data.code === 'ACCOUNT_LOCKED');

  console.log('\n== 10. Rate limiting ==');
  let limited = false;
  for (let i = 0; i < 8; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const r = await call('POST', '/auth/forgot-password', { body: { email: 'nobody@example.com' } });
    if (r.status === 429) { limited = true; break; }
  }
  check('forgot-password rate limited', limited);

  console.log('\n== 11. Two-factor authentication ==');
  const setup = await call('POST', '/security/2fa/setup', { body: {}, cookies: userCookies });
  check('2FA setup returns secret + QR', setup.status === 200 && Boolean(setup.data.secret) && Boolean(setup.data.qrCodeDataUrl));
  const { authenticator } = require('../server/node_modules/otplib');
  const goodCode = authenticator.generate(setup.data.secret);
  const enableBad = await call('POST', '/security/2fa/enable', { body: { code: '000000' }, cookies: userCookies });
  check('2FA enable rejects bad code', enableBad.status === 400);
  const enable = await call('POST', '/security/2fa/enable', { body: { code: goodCode }, cookies: userCookies });
  check('2FA enable succeeds', enable.status === 200 && enable.data.recoveryCodes.length === 10);
  const twoFaCookies = jar();
  const step1 = await call('POST', '/auth/login', { body: { email, password: finalPw }, cookies: twoFaCookies });
  check('login requires 2FA now', step1.status === 200 && step1.data.requiresTwoFactor === true);
  const step2bad = await call('POST', '/auth/login/2fa', { body: { code: '123456' }, cookies: twoFaCookies });
  check('bad 2FA code rejected', step2bad.status === 401);
  const step2 = await call('POST', '/auth/login/2fa', { body: { code: authenticator.generate(setup.data.secret) }, cookies: twoFaCookies });
  check('2FA login completes', step2.status === 200 && step2.data.user.email === email);
  const disable = await call('POST', '/security/2fa/disable', { body: { password: finalPw, code: authenticator.generate(setup.data.secret) }, cookies: twoFaCookies });
  check('2FA disable with password + code', disable.status === 200);

  console.log('\n== 12. Session management ==');
  const sList = await call('GET', '/security/sessions', { cookies: twoFaCookies });
  check('sessions visible after 2FA login', sList.status === 200 && sList.data.sessions.some((s) => s.status === 'active'));
  const logoutOthers = await call('POST', '/security/sessions/logout-others', { body: {}, cookies: twoFaCookies });
  check('logout other devices', logoutOthers.status === 200);
  const logoutAll = await call('POST', '/security/sessions/logout-all', { body: {}, cookies: twoFaCookies });
  check('logout all sessions', logoutAll.status === 200);
  const meAfterAll = await call('GET', '/auth/me', { cookies: twoFaCookies });
  check('revoked session cannot access API', meAfterAll.status === 401);

  console.log('\n== 13. Admin dashboard ==');
  const adminCookies = jar();
  const adminLogin = await call('POST', '/auth/login', { body: { email: 'admin@example.com', password: 'Secure0wner!2026' }, cookies: adminCookies });
  check('admin login', adminLogin.status === 200);
  const adminOverview = await call('GET', '/admin/overview', { cookies: adminCookies });
  check('admin overview', adminOverview.status === 200 && adminOverview.data.users.total >= 1);
  const adminUsers = await call('GET', '/admin/users', { cookies: adminCookies });
  check('admin user list', adminUsers.status === 200 && adminUsers.data.users.length >= 1);
  const adminActivity = await call('GET', '/admin/login-activity?page=1&limit=10', { cookies: adminCookies });
  check('admin login activity', adminActivity.status === 200 && adminActivity.data.total > 0);
  const adminAudit = await call('GET', '/admin/audit-logs?page=1&limit=10', { cookies: adminCookies });
  check('admin audit logs', adminAudit.status === 200 && adminAudit.data.total > 0);
  const nonAdmin = jar();
  await call('POST', '/auth/login', { body: { email, password: finalPw }, cookies: nonAdmin });
  const denied = await call('GET', '/admin/overview', { cookies: nonAdmin });
  check('non-admin blocked from admin API', denied.status === 403);

  console.log('\n== 14. Security headers ==');
  const head = await fetch(`${BASE}/health`);
  check('helmet sets X-Frame-Options', head.headers.get('x-frame-options') !== null);
  check('CORS header present', head.headers.get('access-control-allow-origin') !== null);

  console.log(`\n========================================`);
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  if (failures.length) {
    console.log('Failed checks:');
    failures.forEach((f) => console.log(` - ${f}`));
    process.exit(1);
  }
  process.exit(0);
})().catch((err) => {
  console.error('Verification script crashed:', err);
  process.exit(1);
});
