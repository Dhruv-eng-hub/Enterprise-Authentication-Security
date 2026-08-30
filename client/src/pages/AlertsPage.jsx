import { useCallback, useEffect, useState } from 'react';
import { api, formatDateTime } from '../api';
import { Badge, Card, EmptyState, Message } from '../components/ui';
import Spinner from '../components/Spinner';

const severityIcon = { info: 'ℹ️', warning: '⚠️', critical: '🚨' };

export default function AlertsPage() {
  const [alerts, setAlerts] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [unreadOnly, setUnreadOnly] = useState(false);

  const load = useCallback(() => {
    api.get(`/security/alerts${unreadOnly ? '?unread=1' : ''}`)
      .then((d) => setAlerts(d.alerts))
      .catch((e) => setError(e.message));
  }, [unreadOnly]);

  useEffect(() => { load(); }, [load]);

  const markRead = async (id) => {
    try {
      await api.patch(`/security/alerts/${id}/read`, {});
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  const markAllRead = async () => {
    try {
      const d = await api.patch('/security/alerts/read-all', {});
      setNotice(d.message);
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  if (error && !alerts) return <div className="card"><p>{error}</p></div>;
  if (!alerts) return <Spinner full label="Loading security alerts…" />;

  const unread = alerts.filter((a) => !a.read_at).length;

  return (
    <>
      <h1 className="page-title">Security Alerts</h1>
      <p className="page-subtitle">
        Notifications about sign-ins, password changes and suspicious behavior on your account.
      </p>

      <Message kind="success" onDismiss={() => setNotice('')}>{notice}</Message>
      <Message kind="error" onDismiss={() => setError('')}>{error}</Message>

      <Card
        title={unread > 0 ? `Alerts (${unread} unread)` : 'Alerts'}
        subtitle="Review anything unexpected and secure your account if needed."
        actions={(
          <>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13.5 }}>
              <input type="checkbox" checked={unreadOnly} onChange={(e) => setUnreadOnly(e.target.checked)} />
              Unread only
            </label>
            {unread > 0 && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={markAllRead}>
                Mark all as read
              </button>
            )}
          </>
        )}
      >
        {alerts.length === 0 ? (
          <EmptyState icon="🔕" title="No security alerts" hint="You're all caught up. New alerts will appear here." />
        ) : (
          alerts.map((a) => (
            <div className="list-item" key={a.id} style={{ opacity: a.read_at ? 0.75 : 1 }}>
              <div className="list-icon" aria-hidden="true">{severityIcon[a.severity] || 'ℹ️'}</div>
              <div className="list-body">
                <div className="list-title">
                  {a.title}
                  {!a.read_at && <Badge tone="info">New</Badge>}
                  <Badge tone={a.severity === 'critical' ? 'critical' : a.severity === 'warning' ? 'warning' : 'info'}>
                    {a.severity}
                  </Badge>
                </div>
                <div className="list-sub">{formatDateTime(a.created_at)}</div>
                <p style={{ margin: '6px 0 0', fontSize: 14 }}>{a.message}</p>
              </div>
              {!a.read_at && (
                <div className="list-actions">
                  <button type="button" className="btn btn-ghost btn-sm" onClick={() => markRead(a.id)}>
                    Mark read
                  </button>
                </div>
              )}
            </div>
          ))
        )}
      </Card>
    </>
  );
}
