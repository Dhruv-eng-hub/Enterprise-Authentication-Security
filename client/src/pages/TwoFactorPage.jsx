import { useEffect, useState } from 'react';
import { api } from '../api';
import { useAuth } from '../AuthContext';
import { Card, Message } from '../components/ui';

export default function TwoFactorPage() {
  const { user, refresh } = useAuth();
  const enabled = Boolean(user?.twoFactorEnabled);

  const [step, setStep] = useState('idle'); // idle | setup | enabled-view
  const [setup, setSetup] = useState(null); // { secret, otpauthUrl, qrCodeDataUrl }
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState(null);
  const [password, setPassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [confirmRegenerate, setConfirmRegenerate] = useState(false);

  useEffect(() => {
    if (enabled) setStep('enabled-view');
  }, [enabled]);

  // force === true (strict check — this is also wired as a click handler, so it
  // must never mistake a MouseEvent for the flag) discards the pending key.
  const beginSetup = async (force) => {
    setError('');
    setBusy(true);
    try {
      const data = await api.post('/security/2fa/setup', { force: force === true });
      setSetup(data);
      setStep('setup');
      if (force === true) setNotice('A brand-new key was created. If your authenticator app still shows the old “SecureApp” entry, delete it there first, then scan this new QR.');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const confirmSetup = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await api.post('/security/2fa/enable', { code });
      setRecoveryCodes(data.recoveryCodes);
      setStep('enabled-view');
      setNotice(data.message);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleDisable = async () => {
    setError('');
    setBusy(true);
    try {
      const d = await api.post('/security/2fa/disable', { password, code: disableCode });
      setNotice(d.message);
      setConfirmDisable(false);
      setPassword('');
      setDisableCode('');
      setStep('idle');
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleRegenerate = async () => {
    setError('');
    setBusy(true);
    try {
      const d = await api.post('/security/2fa/recovery-codes', { password });
      setRecoveryCodes(d.recoveryCodes);
      setConfirmRegenerate(false);
      setPassword('');
      setNotice('New recovery codes generated. Old codes are now invalid.');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h1 className="page-title">Two-Factor Authentication</h1>
      <p className="page-subtitle">
        Add a time-based one-time password (TOTP) from an authenticator app as a second sign-in step.
      </p>

      <Message kind="success" onDismiss={() => setNotice('')}>{notice}</Message>
      <Message kind="error" onDismiss={() => setError('')}>{error}</Message>

      <div style={{ maxWidth: 640 }}>
        {step === 'idle' && !enabled && (
          <Card title="2FA is currently off" subtitle="Protect your account with an authenticator app (Google Authenticator, Authy, Microsoft Authenticator…).">
            <ul className="checklist">
              <li><span className="check-ico">1️⃣</span><span>Scan the QR code with your authenticator app.</span></li>
              <li><span className="check-ico">2️⃣</span><span>Enter the 6-digit code to confirm.</span></li>
              <li><span className="check-ico">3️⃣</span><span>Store your one-time recovery codes somewhere safe.</span></li>
            </ul>
            <button type="button" className="btn btn-primary" onClick={() => beginSetup(false)} disabled={busy}>
              {busy ? 'Preparing…' : 'Set up two-factor authentication'}
            </button>
          </Card>
        )}

        {step === 'setup' && setup && (
          <Card title="Step 1 — Scan the QR code" subtitle="Open your authenticator app → “Add account” → “Scan QR code”. Use the scanner inside the app, not your phone's camera app.">
            <div className="qr-box">
              <img src={setup.qrCodeDataUrl} alt="TOTP QR code for your authenticator app" width={300} height={300} />
            </div>
            <p className="cell-sub" style={{ textAlign: 'center' }}>
              Can't scan? Tap to copy the key, then choose “Enter key manually” in your app — copy it exactly, one typo and codes won't match:
            </p>
            <button
              type="button" className="secret-box" title="Copy setup key"
              style={{ cursor: 'pointer', width: '100%', textAlign: 'center', fontFamily: 'monospace' }}
              onClick={() => { navigator.clipboard?.writeText(setup.secret.replace(/\s/g, '')); setNotice('Setup key copied to clipboard.'); }}
            >
              {setup.secret}
            </button>
            <button
              type="button" className="btn btn-ghost btn-sm" style={{ display: 'block', margin: '8px auto 0' }}
              onClick={() => { navigator.clipboard?.writeText(setup.otpauthUrl); setNotice('Setup link copied — open your authenticator app and use its “Add account from link / paste key” option.'); }}
            >
              📋 Copy full setup link (otpauth://…)
            </button>
            <p className="cell-sub" style={{ textAlign: 'center', marginTop: 8 }}>
              Works with Google Authenticator, Microsoft Authenticator, Authy, or Aegis. Scanning must be done from inside one of these apps.
            </p>
            <form onSubmit={confirmSetup} style={{ marginTop: 16 }}>
              <div className="field">
                <label htmlFor="tfa-confirm-code">Verification code</label>
                <input
                  id="tfa-confirm-code" type="text" inputMode="numeric" value={code}
                  onChange={(e) => setCode(e.target.value)} placeholder="123456" required autoFocus
                />
                <p className="cell-sub" style={{ margin: '6px 0 0' }}>Codes rotate every 30 seconds — enter the one your app is showing right now.</p>
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Verifying…' : 'Verify & enable'}</button>
                <button type="button" className="btn btn-ghost" onClick={() => setStep('idle')} disabled={busy}>Cancel</button>
              </div>
              <p className="cell-sub" style={{ marginTop: 12 }}>
                Code not matching? Your app may hold a key from an older setup screen.{' '}
                <button type="button" className="link-btn" onClick={() => beginSetup(true)} disabled={busy}>
                  Start over with a new key
                </button>{' '}
                (then delete the old “SecureApp” entry in your app and scan the fresh QR).
              </p>
            </form>
          </Card>
        )}

        {step === 'enabled-view' && enabled && (
          <>
            <Card title="✅ Two-factor authentication is enabled" subtitle="Your account requires an authenticator code at every sign-in.">
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <button type="button" className="btn btn-ghost" onClick={() => setConfirmRegenerate(true)}>
                  Regenerate recovery codes
                </button>
                <button type="button" className="btn btn-danger" onClick={() => setConfirmDisable(true)}>
                  Disable 2FA
                </button>
              </div>
            </Card>
          </>
        )}

        {recoveryCodes && (
          <Card title="🔑 Recovery codes — save them now" subtitle="Each code works once if you lose access to your authenticator. They will not be shown again.">
            <div className="code-grid">
              {recoveryCodes.map((c) => <span key={c} className="code-chip">{c}</span>)}
            </div>
            <button
              type="button" className="btn btn-ghost btn-sm"
              onClick={() => {
                const blob = new Blob([recoveryCodes.join('\n')], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'recovery-codes.txt';
                a.click();
                URL.revokeObjectURL(url);
              }}
            >
              ⬇ Download as text file
            </button>
          </Card>
        )}
      </div>

      {confirmDisable && (
        <div className="modal-backdrop">
          <div className="modal" role="dialog" aria-modal="true" aria-label="Confirm disabling 2FA">
            <h3>Confirm your identity</h3>
            <div className="field">
              <label htmlFor="dis-password">Current password</label>
              <input id="dis-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </div>
            <div className="field">
              <label htmlFor="dis-code">Authenticator or recovery code</label>
              <input id="dis-code" type="text" value={disableCode} onChange={(e) => setDisableCode(e.target.value)} placeholder="123456 or ABCD-1234" />
            </div>
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={() => setConfirmDisable(false)} disabled={busy}>Cancel</button>
              <button type="button" className="btn btn-danger" onClick={handleDisable} disabled={busy}>{busy ? 'Disabling…' : 'Disable 2FA'}</button>
            </div>
          </div>
        </div>
      )}

      {confirmRegenerate && (
        <div className="modal-backdrop">
          <div className="modal" role="dialog" aria-modal="true" aria-label="Regenerate recovery codes">
            <h3>Regenerate recovery codes?</h3>
            <p>All existing recovery codes stop working immediately.</p>
            <div className="field">
              <label htmlFor="regen-password">Confirm with your password</label>
              <input id="regen-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </div>
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={() => setConfirmRegenerate(false)} disabled={busy}>Cancel</button>
              <button type="button" className="btn btn-primary" onClick={handleRegenerate} disabled={busy}>Generate new codes</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
