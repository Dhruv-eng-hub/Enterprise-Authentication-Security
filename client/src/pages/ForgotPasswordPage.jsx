import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Message } from '../components/ui';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await api.post('/auth/forgot-password', { email });
      setResult(data);
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
          <h1 className="auth-title">Reset your password</h1>
          <p className="auth-sub">Enter your email and we'll send you a secure reset link.</p>

          {result ? (
            <>
              <Message kind="success">{result.message}</Message>
              {result.devEmailUrl && (
                <Message kind="warning">
                  Development mode (no SMTP): <a href={result.devEmailUrl}>open your reset link</a>.
                </Message>
              )}
              <Message kind="info">
                For your protection, we never reveal whether an email address has an account.
              </Message>
            </>
          ) : (
            <>
              <Message kind="error" onDismiss={() => setError('')}>{error}</Message>
              <form onSubmit={submit}>
                <div className="field">
                  <label htmlFor="fp-email">Email</label>
                  <input
                    id="fp-email" type="email" value={email} autoComplete="email"
                    onChange={(e) => setEmail(e.target.value)} required placeholder="you@example.com"
                  />
                </div>
                <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
                  {busy ? 'Sending…' : 'Send reset link'}
                </button>
              </form>
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
