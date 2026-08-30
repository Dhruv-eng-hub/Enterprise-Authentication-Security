import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import PasswordField from '../components/PasswordField';
import { Message } from '../components/ui';

export default function RegisterPage() {
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState([]);
  const [busy, setBusy] = useState(false);
  const [success, setSuccess] = useState(null); // { message, devEmailUrl? }

  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }));

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setFieldErrors([]);
    if (form.password !== form.confirm) {
      setError('Passwords do not match.');
      return;
    }
    setBusy(true);
    try {
      const data = await api.post('/auth/register', {
        name: form.name, email: form.email, password: form.password
      });
      setSuccess({ message: data.message, devEmailUrl: data.devEmailUrl, email: form.email });
    } catch (err) {
      if (err.data?.errors) setFieldErrors(err.data.errors);
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (success) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="auth-brand"><span aria-hidden="true">🛡️</span> SecureApp</div>
          <div className="card">
            <h1 className="auth-title">Check your inbox 📬</h1>
            <p className="auth-sub">{success.message}</p>
            <Message kind="info">
              We sent a verification link to <strong>{success.email}</strong>.
              The link expires shortly, so please verify soon.
            </Message>
            {success.devEmailUrl && (
              <Message kind="warning">
                Development mode (no SMTP): <a href={success.devEmailUrl}>open your verification link</a>.
              </Message>
            )}
            <Link className="btn btn-primary btn-block" to="/resend-verification">
              Didn't receive it? Resend verification email
            </Link>
            <div className="auth-links center">
              <Link to="/login">Already verified? Sign in</Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand"><span aria-hidden="true">🛡️</span> SecureApp</div>
        <div className="card">
          <h1 className="auth-title">Create your account</h1>
          <p className="auth-sub">Enterprise-grade protection for your identity</p>
          <form onSubmit={submit}>
            <div className="field">
              <label htmlFor="reg-name">Full name</label>
              <input
                id="reg-name" type="text" value={form.name} autoComplete="name"
                onChange={(e) => set('name')(e.target.value)} required placeholder="Jane Doe"
              />
            </div>
            <div className="field">
              <label htmlFor="reg-email">Email</label>
              <input
                id="reg-email" type="email" value={form.email} autoComplete="email"
                onChange={(e) => set('email')(e.target.value)} required placeholder="you@example.com"
              />
            </div>
            <PasswordField
              id="reg-password" label="Password" value={form.password}
              onChange={set('password')} autoComplete="new-password" showStrength
            />
            <PasswordField
              id="reg-confirm" label="Confirm password" value={form.confirm}
              onChange={set('confirm')} autoComplete="new-password"
            />
            <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
              {busy ? 'Creating account…' : 'Create account'}
            </button>
            {(error || fieldErrors.length > 0) && (
              <p className="inline-error" role="alert">
                {error}{fieldErrors.length > 0 ? ` ${fieldErrors.join(' ')}` : ''}
              </p>
            )}
          </form>
          <div className="auth-links center">
            <Link to="/login">Already have an account? Sign in</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
