import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, formatDateTime } from '../api';
import { useAuth } from '../AuthContext';
import { Card, ConfirmDialog, EmptyState } from '../components/ui';
import Spinner from '../components/Spinner';

function ScoreRing({ value, max }) {
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(1, value / max));
  const color = pct >= 0.8 ? '#15803d' : pct >= 0.5 ? '#f59e0b' : '#dc2626';
  return (
    <div className="score-ring" role="img" aria-label={`Security score ${value} out of ${max}`}>
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle className="ring-bg" cx="66" cy="66" r={radius} fill="none" strokeWidth="12" />
        <circle
          className="ring-fg" cx="66" cy="66" r={radius} fill="none" strokeWidth="12"
          stroke={color} strokeDasharray={circumference} strokeDashoffset={circumference * (1 - pct)}
        />
      </svg>
      <div className="score-number">
        <strong>{value}</strong>
        <span>of {max}</span>
      </div>
    </div>
  );
}

const recoLinks = {
  'verify-email': '/resend-verification',
  'enable-2fa': '/security/two-factor',
  'rotate-password': '/security/password',
  'review-failures': '/security/activity',
  'review-alerts': '/security/alerts'
};

export default function SecurityDashboardPage() {
  const { signOutEverywhere } = useAuth();
  const navigate = useNavigate();
  const [overview, setOverview] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [error, setError] = useState('');
  const [confirmAll, setConfirmAll] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    Promise.all([api.get('/security/overview'), api.get('/security/timeline')])
      .then(([ov, tl]) => { setOverview(ov); setTimeline(tl.events); })
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => { load(); }, [load]);

  if (error) return <div className="card"><p>{error}</p></div>;
  if (!overview) return <Spinner full label="Loading security dashboard…" />;

  const { stats, score, recommendations } = overview;
  const checks = [
    { ok: stats.emailVerified, text: 'Email verified' },
    { ok: stats.twoFactorEnabled, text: 'Two-factor authentication enabled' },
    { ok: stats.passwordMaxAgeDays <= 0 || stats.passwordAgeDays <= stats.passwordMaxAgeDays, text: 'Password within rotation policy' },
    { ok: stats.failedLogins7d === 0, text: 'No failed sign-ins in the last 7 days' },
    { ok: stats.unreadAlerts === 0, text: 'No unread security alerts' }
  ];

  const handleLogoutAll = async () => {
    setBusy(true);
    try {
      await signOutEverywhere();
      navigate('/login');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h1 className="page-title">Security Dashboard</h1>
      <p className="page-subtitle">Account security, sessions, activity and alerts — all in one place.</p>

      <div className="grid-2">
        <Card title="Security Score" subtitle="How well protected your account is right now.">
          <div className="score-wrap">
            <ScoreRing value={score.value} max={score.max} />
            <div className="score-details">
              {recommendations.length === 0 ? (
                <div className="banner banner-ok">🎉 Excellent! Your account meets every security recommendation.</div>
              ) : (
                <>
                  <strong>Secure your account — recommended actions:</strong>
                  <ul className="reco-list">
                    {recommendations.map((r) => (
                      <li key={r.id}>
                        <span>⚠️ {r.text}</span>
                        <span className="reco-points">+{r.points} pts</span>
                        {recoLinks[r.id] && (
                          <Link className="btn btn-ghost btn-sm" to={recoLinks[r.id]}>Fix</Link>
                        )}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          </div>
        </Card>

        <Card title="Security Overview" subtitle="Current protection status.">
          <ul className="checklist">
            {checks.map((c) => (
              <li key={c.text}>
                <span className="check-ico" aria-hidden="true">{c.ok ? '✅' : '⚠️'}</span>
                <span>{c.text}</span>
              </li>
            ))}
            <li>
              <span className="check-ico" aria-hidden="true">🖥️</span>
              <span>{stats.activeSessions} active session(s) — <Link to="/security/sessions">manage</Link></span>
            </li>
          </ul>
          <div style={{ marginTop: 14, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <Link className="btn btn-ghost btn-sm" to="/security/password">Change password</Link>
            <button type="button" className="btn btn-danger btn-sm" onClick={() => setConfirmAll(true)}>
              Sign out all sessions
            </button>
          </div>
        </Card>
      </div>

      <div className="grid-4">
        <div className="stat-card">
          <div className="stat-label">Last login</div>
          <div className="stat-value" style={{ fontSize: 16 }}>{formatDateTime(stats.lastLoginAt)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Failed attempts (7d)</div>
          <div className="stat-value">{stats.failedLogins7d}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Password age</div>
          <div className="stat-value">{stats.passwordAgeDays}d</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Security alerts</div>
          <div className="stat-value">{stats.unreadAlerts}</div>
          <div className="stat-sub">unread</div>
        </div>
      </div>

      <Card title="Security Event Timeline" subtitle="A unified view of sign-ins, alerts and audited security actions.">
        {!timeline || timeline.length === 0 ? (
          <EmptyState icon="🕓" title="No security events yet" hint="Events will appear here as you use your account." />
        ) : (
          <div className="timeline">
            {timeline.map((ev, i) => (
              <div key={`${ev.at}-${i}`} className={`timeline-item ${ev.severity === 'critical' ? 't-crit' : ev.severity === 'warning' ? 't-warn' : ''}`}>
                <div className="timeline-time">{formatDateTime(ev.at)} · {ev.category}</div>
                <div className="timeline-title">{ev.title}</div>
                {ev.detail && <div className="timeline-detail">{ev.detail}</div>}
              </div>
            ))}
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={confirmAll}
        danger
        busy={busy}
        title="Sign out all sessions?"
        body="This immediately terminates every active session on all devices, including this one. You will need to sign in again."
        confirmLabel="Sign out everywhere"
        onConfirm={handleLogoutAll}
        onCancel={() => setConfirmAll(false)}
      />
    </>
  );
}
