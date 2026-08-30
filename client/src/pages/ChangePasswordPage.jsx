import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import PasswordField from '../components/PasswordField';
import { Card, Message } from '../components/ui';

export default function ChangePasswordPage() {
  const navigate = useNavigate();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState([]);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setFieldErrors([]);
    if (next !== confirm) {
      setError('New passwords do not match.');
      return;
    }
    setBusy(true);
    try {
      const d = await api.post('/auth/change-password', { currentPassword: current, newPassword: next });
      setNotice(d.message);
      // All sessions are revoked after a password change — return to sign-in.
      setTimeout(() => navigate('/login'), 1800);
    } catch (err) {
      if (err.data?.errors) setFieldErrors(err.data.errors);
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h1 className="page-title">Change Password</h1>
      <p className="page-subtitle">
        Your current password is required. Recently used passwords cannot be reused,
        and all sessions are signed out after a change.
      </p>

      <div style={{ maxWidth: 560 }}>
        <Card>
          <Message kind="success">{notice}</Message>
          <form onSubmit={submit}>
            <PasswordField
              id="cp-current" label="Current password" value={current}
              onChange={setCurrent} autoComplete="current-password"
            />
            <PasswordField
              id="cp-new" label="New password" value={next}
              onChange={setNext} autoComplete="new-password" showStrength
            />
            <PasswordField
              id="cp-confirm" label="Confirm new password" value={confirm}
              onChange={setConfirm} autoComplete="new-password"
            />
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Updating…' : 'Update password'}
            </button>
            {(error || fieldErrors.length > 0) && (
              <p className="inline-error" role="alert">
                {error}{fieldErrors.length > 0 ? ` ${fieldErrors.join(' ')}` : ''}
              </p>
            )}
          </form>
        </Card>
      </div>
    </>
  );
}
