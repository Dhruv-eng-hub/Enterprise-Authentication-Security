import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import PasswordField from '../components/PasswordField';
import { Message } from '../components/ui';

export default function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState([]);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setFieldErrors([]);
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    setBusy(true);
    try {
      await api.post('/auth/reset-password', { token, password });
      setDone(true);
    } catch (err) {
      if (err.data?.errors) setFieldErrors(err.data.errors);
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
          {done ? (
            <>
              <h1 className="auth-title">Password updated ✅</h1>
              <p className="auth-sub">Your password has been reset and all active sessions were signed out.</p>
              <Link className="btn btn-primary btn-block" to="/login">Sign in with your new password</Link>
            </>
          ) : !token ? (
            <>
              <h1 className="auth-title">Invalid reset link</h1>
              <p className="auth-sub">This link is missing its security token. Please request a new reset link.</p>
              <Link className="btn btn-primary btn-block" to="/forgot-password">Request a new link</Link>
            </>
          ) : (
            <>
              <h1 className="auth-title">Choose a new password</h1>
              <p className="auth-sub">For your safety, all existing sessions will be signed out.</p>
              <Message kind="error" onDismiss={() => { setError(''); setFieldErrors([]); }}>
                {error}
                {fieldErrors.length > 0 && (
                  <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                    {fieldErrors.map((fe) => <li key={fe}>{fe}</li>)}
                  </ul>
                )}
              </Message>
              <form onSubmit={submit} noValidate>
                <PasswordField
                  id="rp-password" label="New password" value={password}
                  onChange={setPassword} autoComplete="new-password" showStrength
                />
                <PasswordField
                  id="rp-confirm" label="Confirm new password" value={confirm}
                  onChange={setConfirm} autoComplete="new-password"
                />
                <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
                  {busy ? 'Resetting…' : 'Reset password'}
                </button>
              </form>
              <div className="auth-links center">
                <Link to="/forgot-password">Link expired? Request a new one</Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
