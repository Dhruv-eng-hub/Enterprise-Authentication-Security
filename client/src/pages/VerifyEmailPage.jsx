import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import { Message } from '../components/ui';
import Spinner from '../components/Spinner';

/**
 * Handles both modes:
 *  - /verify-email?token=...   → validates the token from the email link
 *  - /resend-verification      → lets the user request a fresh link
 */

// React StrictMode runs effects twice in development; without this guard the
// one-time verification token would be POSTed twice and the second (duplicate)
// "already used" response would be shown. Both runs share one in-flight request.
const verifyPromises = new Map();

export default function VerifyEmailPage({ resendMode = false }) {
  const [params] = useSearchParams();
  const token = params.get('token') || '';

  const [state, setState] = useState(resendMode ? 'resend-form' : token ? 'verifying' : 'no-token');
  const [message, setMessage] = useState('');
  const [devEmailUrl, setDevEmailUrl] = useState('');
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (state !== 'verifying' || !token) return;
    if (!verifyPromises.has(token)) {
      verifyPromises.set(
        token,
        api.post('/auth/verify-email', { token }).finally(() => {
          // Clear after a short grace period so StrictMode's second effect run
          // (and instant back/forward navigation) still shares this request.
          setTimeout(() => verifyPromises.delete(token), 2000);
        })
      );
    }
    verifyPromises.get(token)
      .then((data) => {
        setMessage(data.message);
        setState('success');
      })
      .catch((err) => {
        setError(err.message);
        setState(err.data?.expired ? 'expired' : 'failed');
      });
  }, [state, token]);

  const submitResend = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await api.post('/auth/resend-verification', { email });
      setMessage(data.message);
      setDevEmailUrl(data.devEmailUrl || '');
      setState('resent');
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand"><span aria-hidden="true">🛡️</span> SecureApp</div>
        <div className="card">
          {state === 'verifying' && <Spinner label="Verifying your email…" />}

          {state === 'success' && (
            <>
              <h1 className="auth-title">Email verified ✅</h1>
              <p className="auth-sub">{message} Your account is now active.</p>
              <Link className="btn btn-primary btn-block" to="/login">Continue to sign in</Link>
            </>
          )}

          {(state === 'failed' || state === 'expired') && (
            <>
              <h1 className="auth-title">Verification failed</h1>
              <Message kind="error">{error}</Message>
              <button type="button" className="btn btn-primary btn-block"
                onClick={() => setState('resend-form')}>
                Request a new verification link
              </button>
            </>
          )}

          {state === 'no-token' && (
            <>
              <h1 className="auth-title">Verify your email</h1>
              <p className="auth-sub">Open the link from your verification email, or request a new one below.</p>
              <button type="button" className="btn btn-primary btn-block" onClick={() => setState('resend-form')}>
                Request a new verification link
              </button>
            </>
          )}

          {state === 'resend-form' && (
            <>
              <h1 className="auth-title">Resend verification email</h1>
              <p className="auth-sub">Enter the email you registered with and we'll send a fresh link.</p>
              <Message kind="error" onDismiss={() => setError('')}>{error}</Message>
              <form onSubmit={submitResend}>
                <div className="field">
                  <label htmlFor="rv-email">Email</label>
                  <input
                    id="rv-email" type="email" value={email} autoComplete="email"
                    onChange={(e) => setEmail(e.target.value)} required placeholder="you@example.com"
                  />
                </div>
                <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
                  {busy ? 'Sending…' : 'Resend verification email'}
                </button>
              </form>
            </>
          )}

          {state === 'resent' && (
            <>
              <h1 className="auth-title">Check your inbox 📬</h1>
              <Message kind="success">{message}</Message>
              {devEmailUrl && (
                <Message kind="warning">
                  Development mode (no SMTP): <a href={devEmailUrl}>open your verification link</a>.
                </Message>
              )}
              <button type="button" className="btn btn-ghost btn-block" onClick={() => setState('resend-form')}>
                Send again
              </button>
            </>
          )}

          <div className="auth-links center">
            <Link to="/login">← Back to sign in</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
