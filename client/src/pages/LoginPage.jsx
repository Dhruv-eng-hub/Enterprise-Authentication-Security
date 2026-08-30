import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import PasswordField from '../components/PasswordField';
import { Message } from '../components/ui';

export default function LoginPage() {
  const { login, loginTwoFactor } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [step, setStep] = useState('credentials'); // credentials | twoFactor
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submitCredentials = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const result = await login(email, password);
      if (result.requiresTwoFactor) {
        setStep('twoFactor');
      } else {
        navigate('/security');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const submitTwoFactor = async (e) => {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await loginTwoFactor(code.trim());
      navigate('/security');
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
          {step === 'credentials' ? (
            <>
              <h1 className="auth-title">Welcome back</h1>
              <p className="auth-sub">Sign in to your secure account</p>
              <Message kind="error" onDismiss={() => setError('')}>{error}</Message>
              <form onSubmit={submitCredentials} noValidate>
                <div className="field">
                  <label htmlFor="login-email">Email</label>
                  <input
                    id="login-email" type="email" value={email} autoComplete="email"
                    onChange={(e) => setEmail(e.target.value)} required placeholder="you@example.com"
                  />
                </div>
                <PasswordField
                  id="login-password" label="Password" value={password}
                  onChange={setPassword} autoComplete="current-password"
                />
                <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
                  {busy ? 'Signing in…' : 'Sign in'}
                </button>
              </form>
              <div className="auth-links">
                <Link to="/forgot-password">Forgot password?</Link>
                <Link to="/register">Create an account</Link>
              </div>
            </>
          ) : (
            <>
              <h1 className="auth-title">Two-factor verification</h1>
              <p className="auth-sub">Enter the 6-digit code from your authenticator app, or a recovery code.</p>
              <Message kind="error" onDismiss={() => setError('')}>{error}</Message>
              <form onSubmit={submitTwoFactor}>
                <div className="field">
                  <label htmlFor="tfa-code">Verification code</label>
                  <input
                    id="tfa-code" type="text" inputMode="numeric" autoComplete="one-time-code"
                    value={code} onChange={(e) => setCode(e.target.value)}
                    placeholder="123456 or recovery code" required autoFocus
                  />
                </div>
                <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
                  {busy ? 'Verifying…' : 'Verify & sign in'}
                </button>
              </form>
              <div className="auth-links center">
                <Link to="/login" onClick={() => { setStep('credentials'); setError(''); setCode(''); }}>
                  ← Back to sign in
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
