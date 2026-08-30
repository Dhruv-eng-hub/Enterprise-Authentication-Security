import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, formatDateTime } from '../api';
import { useAuth } from '../AuthContext';
import { Card } from '../components/ui';
import Spinner from '../components/Spinner';

export default function HomePage() {
  const { user } = useAuth();
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get('/security/overview').then(setOverview).catch((err) => setError(err.message));
  }, []);

  if (error) return <div className="card"><p>{error}</p></div>;
  if (!overview) return <Spinner full label="Loading your security overview…" />;

  const { stats } = overview;
  return (
    <>
      <h1 className="page-title">Welcome back, {user.name} 👋</h1>
      <p className="page-subtitle">Here's the security posture of your account at a glance.</p>

      <div className="grid-4">
        <div className="stat-card">
          <div className="stat-label">Security score</div>
          <div className="stat-value">{overview.score.value}/100</div>
          <div className="stat-sub"><Link to="/security">View recommendations</Link></div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active sessions</div>
          <div className="stat-value">{stats.activeSessions}</div>
          <div className="stat-sub"><Link to="/security/sessions">Manage sessions</Link></div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Unread alerts</div>
          <div className="stat-value">{stats.unreadAlerts}</div>
          <div className="stat-sub"><Link to="/security/alerts">Review alerts</Link></div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last sign-in</div>
          <div className="stat-value" style={{ fontSize: 17 }}>{formatDateTime(stats.lastLoginAt)}</div>
          <div className="stat-sub"><Link to="/security/activity">Full history</Link></div>
        </div>
      </div>

      <Card title="Quick security actions" subtitle="The fastest ways to harden your account.">
        <ul className="checklist">
          <li>
            <span className="check-ico" aria-hidden="true">{stats.twoFactorEnabled ? '✅' : '🔒'}</span>
            <div>
              <strong>Two-factor authentication</strong>
              <div className="cell-sub">{stats.twoFactorEnabled ? 'Enabled — great!' : 'Add an extra layer of protection.'}</div>
            </div>
            <div className="list-actions"><Link className="btn btn-ghost btn-sm" to="/security/two-factor">Manage</Link></div>
          </li>
          <li>
            <span className="check-ico" aria-hidden="true">🔑</span>
            <div>
              <strong>Password age: {stats.passwordAgeDays} day(s)</strong>
              <div className="cell-sub">
                {stats.passwordMaxAgeDays > 0
                  ? `Policy requires rotation every ${stats.passwordMaxAgeDays} days.`
                  : 'No expiration policy configured.'}
              </div>
            </div>
            <div className="list-actions"><Link className="btn btn-ghost btn-sm" to="/security/password">Change</Link></div>
          </li>
          <li>
            <span className="check-ico" aria-hidden="true">📧</span>
            <div>
              <strong>Email verification</strong>
              <div className="cell-sub">{stats.emailVerified ? 'Verified.' : 'Verify your email to unlock all features.'}</div>
            </div>
          </li>
        </ul>
      </Card>
    </>
  );
}
