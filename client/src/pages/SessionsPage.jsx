import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, formatDateTime, timeAgo } from '../api';
import { useAuth } from '../AuthContext';
import { Badge, Card, ConfirmDialog, EmptyState, Message } from '../components/ui';
import Spinner from '../components/Spinner';

export default function SessionsPage() {
  const { signOutEverywhere } = useAuth();
  const navigate = useNavigate();
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [confirmTarget, setConfirmTarget] = useState(null); // session to revoke | 'others' | 'all'
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.get('/security/sessions').then((d) => setSessions(d.sessions)).catch((e) => setError(e.message));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleConfirm = async () => {
    setBusy(true);
    setError('');
    try {
      if (confirmTarget === 'all') {
        await signOutEverywhere();
        navigate('/login');
        return;
      }
      if (confirmTarget === 'others') {
        const d = await api.post('/security/sessions/logout-others', {});
        setNotice(d.message);
      } else {
        const d = await api.delete(`/security/sessions/${confirmTarget.id}`);
        setNotice(d.message);
      }
      setConfirmTarget(null);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (error && !sessions) return <div className="card"><p>{error}</p></div>;
  if (!sessions) return <Spinner full label="Loading sessions…" />;

  const active = sessions.filter((s) => s.status === 'active');
  const history = sessions.filter((s) => s.status !== 'active').slice(0, 10);

  return (
    <>
      <h1 className="page-title">Active Sessions</h1>
      <p className="page-subtitle">Every device signed into your account. Revoke anything you don't recognise.</p>

      <Message kind="success" onDismiss={() => setNotice('')}>{notice}</Message>
      <Message kind="error" onDismiss={() => setError('')}>{error}</Message>

      <Card
        title={`Current devices (${active.length})`}
        subtitle="A new sign-in from another device automatically terminates older sessions under the single-session policy."
        actions={(
          <>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setConfirmTarget('others')}>
              Sign out other devices
            </button>
            <button type="button" className="btn btn-danger btn-sm" onClick={() => setConfirmTarget('all')}>
              Sign out all sessions
            </button>
          </>
        )}
      >
        {active.length === 0 ? (
          <EmptyState icon="💤" title="No active sessions" hint="Something is wrong — you should be signed in!" />
        ) : (
          active.map((s) => (
            <div className="list-item" key={s.id}>
              <div className="list-icon" aria-hidden="true">{s.device === 'Mobile' ? '📱' : s.device === 'Tablet' ? '📟' : '💻'}</div>
              <div className="list-body">
                <div className="list-title">
                  {s.browser} • {s.os}
                  {Boolean(s.is_current) && <Badge tone="ok">This device</Badge>}
                </div>
                <div className="list-sub">
                  {s.device} · IP {s.ip_address} · Started {formatDateTime(s.created_at)} ·
                  {s.is_current ? ' Active now' : ` Last active ${timeAgo(s.last_active_at)}`}
                </div>
              </div>
              {!Boolean(s.is_current) && (
                <div className="list-actions">
                  <button type="button" className="btn btn-danger btn-sm" onClick={() => setConfirmTarget(s)}>
                    Revoke
                  </button>
                </div>
              )}
            </div>
          ))
        )}
      </Card>

      {history.length > 0 && (
        <Card title="Recent session history" subtitle="Sessions that were revoked, terminated or expired.">
          {history.map((s) => (
            <div className="list-item" key={s.id}>
              <div className="list-icon" aria-hidden="true">🗄️</div>
              <div className="list-body">
                <div className="list-title">
                  {s.browser} • {s.os}
                  <Badge tone={s.status === 'expired' ? 'info' : 'warn'}>{s.status}</Badge>
                </div>
                <div className="list-sub">
                  Started {formatDateTime(s.created_at)} · Closed {formatDateTime(s.revoked_at)}
                </div>
              </div>
            </div>
          ))}
        </Card>
      )}

      <ConfirmDialog
        open={Boolean(confirmTarget)}
        danger
        busy={busy}
        title={
          confirmTarget === 'all' ? 'Sign out all sessions?'
            : confirmTarget === 'others' ? 'Sign out all other devices?'
              : 'Revoke this session?'
        }
        body={
          confirmTarget === 'all'
            ? 'Every device — including this one — will be signed out immediately.'
            : confirmTarget === 'others'
              ? 'All sessions except the current device will be terminated immediately.'
              : `${confirmTarget?.browser} on ${confirmTarget?.os} will be signed out immediately and its access revoked.`
        }
        confirmLabel={confirmTarget === 'all' ? 'Sign out everywhere' : 'Revoke'}
        onConfirm={handleConfirm}
        onCancel={() => setConfirmTarget(null)}
      />
    </>
  );
}
