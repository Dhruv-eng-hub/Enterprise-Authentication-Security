# Enterprise-Level Authentication & Security

A production-grade, full-stack authentication and security module implementing enterprise security controls end-to-end: email verification, strong password policy with history, secure password reset, account lockout, login activity tracking with anomaly detection, session/device management, security alerts, a security score dashboard, optional TOTP two-factor authentication, audit logging, rate limiting, and an admin security monitoring dashboard.

**Stack:** Node.js + Express + SQLite (`better-sqlite3`) on the backend · React 18 + Vite on the frontend · no external services required to run locally.

---

## ✨ Feature Overview

| Area | What's implemented |
|---|---|
| Registration | Email verification with hashed one-time tokens (60 min expiry), resend with rate limiting, duplicate-email protection |
| Password policy | 8–128 chars, upper/lower/number/special required, common-password blocklist, rejects identity-derived passwords (name/email), live Weak/Fair/Good/Strong meter with requirements checklist |
| Password change | Requires current password, blocks reuse of the last **5** passwords (bcrypt-hashed history), invalidates all sessions, 90-day max-age advisory |
| Password reset | Hashed one-time tokens (30 min expiry), generic responses (no account enumeration), resets all sessions on completion |
| Account lockout | 5 failed attempts → 15 min lock, progressive lockout on repeat offenses, safe user-facing messages, admin unlock |
| Login tracking | Every attempt recorded with timestamp, IP, browser/OS/device, and status (`SUCCESS`, `FAILED`, `BLOCKED`, `LOCKED`, `SUSPICIOUS`) |
| Anomaly detection | Flags new browser/OS/IP and off-hours sign-ins, creates alerts, marks activity `SUSPICIOUS` |
| Sessions | DB-backed sessions, token hashed at rest, HttpOnly + SameSite cookies, sliding **30-min inactivity** expiry capped by **12-h max lifetime**, single-session policy (configurable), view/revoke/revoke-all devices |
| Security alerts | New device, multiple failed logins, account locked, password changed, 2FA enabled/disabled — with severity levels and read/unread state |
| Security dashboard | `/security` — 100-point **security score** with breakdown + personalized recommendations, security event timeline, CSV export of login history |
| Two-factor auth | Optional TOTP (Google/Microsoft/Authy compatible), QR-code setup, encrypted secret at rest (AES-256-GCM), 10 hashed backup recovery codes, requires password + code to disable |
| Admin dashboard | Organization-wide users/sessions/sign-ins/alerts/audit views, unlock accounts, revoke user sessions, role-protected APIs |
| Audit logs | Immutable trail of registration, verification, logins, lockouts, password changes/resets, 2FA events, admin actions |
| Hardening | Helmet security headers, CORS allowlist, express-rate-limit (general + stricter auth/resend/forgot windows), bcrypt(12) hashing, timing-equalized login, generic errors, input sanitization, redacting logger, no secrets in code or logs |

---

## 🚀 Getting Started

### Prerequisites
- **Node.js 18+** (tested on Node 22)
- No database server needed — SQLite is embedded (`server/data/app.db` is created automatically)

### Installation

```bash
# 1. Install dependencies (root, server, client)
npm install
npm run install:all

# 2. Configure the server
cd server
copy .env.example .env        # Windows PowerShell: Copy-Item .env.example .env
# Then edit .env — at minimum set a random SERVER_SECRET (see below)
cd ..

# 3. Run both apps
npm run dev
```

- API → http://localhost:5000 (health check: `GET /api/health`)
- Frontend → http://localhost:5173

**Generate a `SERVER_SECRET`:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Seeded administrator account
On first boot the server creates an admin from `.env`:

| Email | Password |
|---|---|
| `admin@example.com` | `Secure0wner!2026` |

> Change this immediately via **Security → Change password** in a real deployment.

### Emails in development
With `SMTP_HOST` empty, emails are printed to the server console **and** action links are returned in API responses (`devEmailUrl`) so every flow is testable without a mail server. Configure `SMTP_*` in `.env` for real delivery.

---

## 🧪 Testing Every Feature

### Automated end-to-end verification
With the server running on port 5000:

```bash
node scripts/verify.js
```

This executes **58 assertions** covering every flow below: registration policy, email verification (incl. token reuse), login blocking pre-verification, sessions, security score, login activity + CSV export, alerts, timeline, password change + history reuse block, password reset (incl. single-use tokens), account lockout (423), rate limiting (429), the full 2FA lifecycle (setup → enable → challenged login → disable), session revocation, admin APIs + authorization, and security headers.

### Manual walkthrough

1. **Register + verification** — `/register` with a weak password (rejected with reasons), then a strong one. Copy the `devEmailUrl` from the server console/API and open `/verify-email?token=…`. Login is blocked until verification.
2. **Password strength UI** — the register/change forms show a live strength meter (Weak/Fair/Good/Strong) and a requirements checklist; try `Password123!` (blocked as common) and your own email as the password (blocked as identity-derived).
3. **Login & lockout** — enter a wrong password 5× at `/login`; on the 5th the account locks (15 min, progressive). Admin can unlock via **Admin → Accounts**.
4. **Rate limiting** — hammer `/forgot-password` (5 req/15 min) to receive `429`.
5. **Security center** — after login visit:
   - `/security` — score gauge, breakdown, recommendations, event timeline
   - `/security/activity` — filterable, paginated login history + **Export CSV**
   - `/security/sessions` — current/other devices, revoke one or all
   - `/security/alerts` — notifications with severity + mark as read
6. **Change password** — `/security/password`: wrong current password rejected, reusing your current or a recent password rejected, all sessions invalidated on success.
7. **Password reset** — `/forgot-password` (identical response for unknown emails), follow the reset link, set a new password; old sessions die, reset token is single-use.
8. **Two-factor auth** — `/security/2fa`: scan the QR with an authenticator app (or type the key), confirm with the 6-digit code, save the 10 recovery codes. Log out and back in — the 2FA step is now required. Disable requires password + code.
9. **Admin dashboard** — log in as admin → `/admin`: org stats, accounts (unlock / revoke sessions), global login activity, alerts, and audit logs. Non-admin users receive `403`.
10. **Session lifetime** — set `SESSION_INACTIVITY_MINUTES=1` in `.env`, restart, log in, wait a minute, and any API call returns `401`.

---

## 🗂️ Project Structure

```
├── package.json                  # Workspace scripts (install:all, dev, build)
├── scripts/
│   └── verify.js                 # 58-assertion end-to-end verification suite
├── server/                       # Express API (:5000)
│   ├── .env.example              # All policies configurable via environment
│   └── src/
│       ├── index.js              # Bootstrap, middleware pipeline, admin seed
│       ├── config.js             # Centralized, env-driven configuration
│       ├── db.js                 # SQLite schema (10 tables), WAL mode
│       ├── routes/               # auth.js · security.js · admin.js
│       ├── services/             # authService · sessionService · securityService · emailService
│       ├── middleware/           # security.js (auth/roles/rate-limit/CORS/cookies) · errorHandler.js
│       └── utils/                # crypto · passwordPolicy · request (device parsing) · logger (redacting)
└── client/                       # React 18 + Vite SPA (:5173)
    └── src/
        ├── App.jsx               # Routes + auth/admin guards
        ├── AuthContext.jsx       # Session state, /auth/me bootstrap
        ├── api.js                # fetch wrapper with credentials + error normalization
        ├── components/           # Layout, PasswordField (strength meter), UI kit, Spinner
        └── pages/                # Login, Register, VerifyEmail, Forgot/ResetPassword, Home,
                                  # SecurityDashboard, Activity, Sessions, Alerts, 2FA,
                                  # ChangePassword, Admin
```

---

## 🔐 Security Design Notes

- **Nothing sensitive is stored in plaintext** — passwords use bcrypt (12 rounds), one-time tokens and recovery codes are SHA-256 hashed, session tokens are hashed at rest, and 2FA secrets are encrypted with AES-256-GCM using `SERVER_SECRET`.
- **Enumeration resistance** — forgot-password, resend-verification, and login all return generic, indistinguishable responses; login time is equalized for unknown emails via a dummy bcrypt comparison.
- **Cookies** — `HttpOnly`, `SameSite=Lax`, `Secure` in production; a same-origin guard rejects cross-origin mutations.
- **2FA challenges** are single-use on success, short-lived (5 min), and retry-bounded by the auth rate limiter.
- **All security policies are env-configurable** (see `server/.env.example`) — lockout thresholds, session lifetimes, password history depth, rate-limit windows, token TTLs.
- **Audit log is append-only** and includes actor, action, details, IP, and timestamp.

## 🌐 Environment Variables

Every setting lives in `server/.env.example` with inline documentation: runtime, DB path, crypto secret, session policy, lockout policy, password policy, token TTLs, rate limits, admin seed, SMTP, and TOTP issuer.

## 📦 Build for production

```bash
npm run build        # builds the client to client/dist
NODE_ENV=production npm start   # API; serve client/dist behind it or any static host
```

In production set `SERVER_SECRET`, strong `ADMIN_*` credentials, `CLIENT_ORIGIN`, and SMTP; cookies automatically gain the `Secure` flag.
