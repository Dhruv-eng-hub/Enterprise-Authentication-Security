import { useCallback, useEffect, useState } from 'react';
import { api, formatDateTime } from '../api';
import { Badge, Card, ConfirmDialog, EmptyState, Message, Pagination, StatusPill } from '../components/ui';
import Spinner from '../components/Spinner';

export default function AdminPage() {
  const [overview, setOverview] = useState(null);
  const [users, setUsers] = useState(null);
  const [activity, setActivity] = useState(null);
  const [alerts, setAlerts] = useState(null);
  const [audit, setAudit] = useState(null);
  const [tab, setTab] = useState('users'); // users | activity | alerts | audit
  const [page, setPage] = useState(1);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [confirmAction, setConfirmAction] = useState(null); // { type: 'unlock'|'revoke', user }

  const loadOverview = useCallback(() => {
    api.get('/admin/overview').then(setOverview).catch((e) => setError(e.message));
  }, []);

  const loadTab = useCallback(() => {
    setError('');
    if (tab === 'users') {
      api.get('/admin/users').then((d) => setUsers(d.users)).catch((e) => setError(e.message));
    } else if (tab === 'activity') {
      api.get(`/admin/login-activity?page=${page}&limit=20`).then(setActivity).catch((e) => setError(e.message));
    } else if (tab === 'alerts') {
      api.get('/admin/alerts').then((d) => setAlerts(d.alerts)).catch((e) => setError(e.message));
    } else {
      api.get(`/admin/audit-logs?page=${page}&limit=20`).then(setAudit).catch((e) => setError(e.message));
    }
  }, [tab, page]);

  useEffect(() => { loadOverview(); }, [loadOverview]);
  useEffect(() => { loadTab(); }, [loadTab]);

  const runAction = async () => {
    setNotice('');
    try {
      const { type, user } = confirmAction;
      const d = type === 'unlock'
        ? await api.post(`/admin/users/${user.id}/unlock`, {})
        : await api.post(`/admin/users/${user.id}/revoke-sessions`, {});
      setNotice(d.message);
      setConfirmAction(null);
      loadTab();
      loadOverview();
    } catch (err) {
      setError(err.message);
      setConfirmAction(null);
    }
  };

  if (!overview) return <Spinner full label="Loading admin dashboard…" />;

  const isLocked = (u) => u.locked_until && new Date(u.locked_until) > new Date();

  return (
    <>
      <h1 className="page-title">Admin — Security Monitoring</h1>
      <p className="page-subtitle">Organization-wide visibility into accounts, sessions, sign-ins and the audit trail.</p>

      <Message kind="success" onDismiss={() => setNotice('')}>{notice}</Message>
      <Message kind="error" onDismiss={() => setError('')}>{error}</Message>

      <div className="grid-4">
        <div className="stat-card">
          <div className="stat-label">Users</div>
          <div className="stat-value">{overview.users.total}</div>
          <div className="stat-sub">{overview.users.verified} verified · {overview.users.twoFactor} with 2FA</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Locked accounts</div>
          <div className="stat-value">{overview.users.locked}</div>
          <div className="stat-sub">brute-force protection</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active sessions</div>
          <div className="stat-value">{overview.sessions.active}</div>
          <div className="stat-sub">across all users</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Sign-ins (24h)</div>
          <div className="stat-value">{overview.activity.total24h}</div>
          <div className="stat-sub">{overview.activity.failed24h} failed · {overview.activity.suspicious24h} suspicious</div>
        </div>
      </div>

      <Card>
        <div className="toolbar">
          {[
            ['users', 'Accounts'],
            ['activity', 'Login Activity'],
            ['alerts', 'Alerts'],
            ['audit', 'Audit Logs']
          ].map(([key, label]) => (
            <button
              key={key} type="button"
              className={`btn btn-sm ${tab === key ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => { setTab(key); setPage(1); }}
            >
              {label}
            </button>
          ))}
          {overview.alerts.unreadCritical > 0 && (
            <Badge tone="critical">{overview.alerts.unreadCritical} critical alert(s) unread</Badge>
          )}
        </div>

        {tab === 'users' && (
          !users ? <Spinner /> : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>User</th><th>Status</th><th>2FA</th><th>Failed attempts</th>
                    <th>Sessions</th><th>Last login</th><th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <div className="cell-main">{u.name} {u.role === 'admin' && <Badge tone="info">admin</Badge>}</div>
                        <div className="cell-sub">{u.email}</div>
                      </td>
                      <td>
                        {!u.email_verified ? <Badge tone="warn">unverified</Badge>
                          : isLocked(u) ? <Badge tone="critical">locked</Badge>
                            : <Badge tone="success">active</Badge>}
                      </td>
                      <td>{u.twofa_enabled ? '✅' : '—'}</td>
                      <td>{u.failed_login_attempts}</td>
                      <td>{u.active_sessions}</td>
                      <td className="cell-sub">{formatDateTime(u.last_login_at)}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {isLocked(u) && (
                            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setConfirmAction({ type: 'unlock', user: u })}>
                              Unlock
                            </button>
                          )}
                          {u.active_sessions > 0 && (
                            <button type="button" className="btn btn-danger btn-sm" onClick={() => setConfirmAction({ type: 'revoke', user: u })}>
                              Revoke sessions
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}

        {tab === 'activity' && (
          !activity ? <Spinner /> : activity.items.length === 0 ? (
            <EmptyState icon="🗂️" title="No login activity yet" />
          ) : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr><th>Status</th><th>User</th><th>Device</th><th>IP</th><th>When</th><th>Reason</th></tr>
                  </thead>
                  <tbody>
                    {activity.items.map((r) => (
                      <tr key={r.id}>
                        <td><StatusPill status={r.status} /></td>
                        <td className="cell-sub">{r.user_email || 'unknown'}</td>
                        <td>{r.browser} • {r.os}</td>
                        <td className="cell-sub">{r.ip_address}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>{formatDateTime(r.created_at)}</td>
                        <td className="cell-sub">{r.reason || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={activity.page} totalPages={activity.totalPages} onPage={setPage} />
            </>
          )
        )}

        {tab === 'alerts' && (
          !alerts ? <Spinner /> : alerts.length === 0 ? (
            <EmptyState icon="🔕" title="No security alerts" />
          ) : (
            alerts.map((a) => (
              <div className="list-item" key={a.id}>
                <div className="list-icon" aria-hidden="true">{a.severity === 'critical' ? '🚨' : a.severity === 'warning' ? '⚠️' : 'ℹ️'}</div>
                <div className="list-body">
                  <div className="list-title">{a.title} <Badge tone={a.severity === 'critical' ? 'critical' : a.severity === 'warning' ? 'warning' : 'info'}>{a.severity}</Badge></div>
                  <div className="list-sub">{a.user_email} · {formatDateTime(a.created_at)}</div>
                  <p style={{ margin: '4px 0 0', fontSize: 14 }}>{a.message}</p>
                </div>
              </div>
            ))
          )
        )}

        {tab === 'audit' && (
          !audit ? <Spinner /> : audit.items.length === 0 ? (
            <EmptyState icon="📜" title="No audit entries yet" />
          ) : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr><th>Action</th><th>Actor</th><th>Details</th><th>IP</th><th>When</th></tr>
                  </thead>
                  <tbody>
                    {audit.items.map((l, i) => (
                      <tr key={`${l.created_at}-${i}`}>
                        <td className="cell-main">{l.action.replaceAll('_', ' ')}</td>
                        <td className="cell-sub">{l.actor_email || '—'}</td>
                        <td className="cell-sub">{l.details || '—'}</td>
                        <td className="cell-sub">{l.ip_address || '—'}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>{formatDateTime(l.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={audit.page} totalPages={audit.totalPages} onPage={setPage} />
            </>
          )
        )}
      </Card>

      <ConfirmDialog
        open={Boolean(confirmAction)}
        danger={confirmAction?.type === 'revoke'}
        title={confirmAction?.type === 'unlock' ? `Unlock ${confirmAction?.user.email}?` : `Revoke all sessions of ${confirmAction?.user.email}?`}
        body={confirmAction?.type === 'unlock'
          ? 'The failed-attempt counter is reset and the lockout is lifted. This action is recorded in the audit log.'
          : 'All of this user\'s active sessions will be terminated immediately. This action is recorded in the audit log.'}
        confirmLabel={confirmAction?.type === 'unlock' ? 'Unlock account' : 'Revoke sessions'}
        onConfirm={runAction}
        onCancel={() => setConfirmAction(null)}
      />
    </>
  );
}
