import { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';

const navItems = [
  { to: '/', label: 'Overview', end: true },
  { to: '/security', label: 'Security Dashboard', end: true },
  { to: '/security/activity', label: 'Login Activity' },
  { to: '/security/sessions', label: 'Sessions' },
  { to: '/security/alerts', label: 'Alerts' },
  { to: '/security/password', label: 'Password' },
  { to: '/security/two-factor', label: 'Two-Factor' }
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <NavLink to="/security" className="brand" aria-label="SecureApp home">
            <span className="brand-shield" aria-hidden="true">🛡️</span>
            <span>SecureApp</span>
          </NavLink>
          <button
            type="button"
            className="menu-toggle"
            aria-label="Toggle navigation menu"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((v) => !v)}
          >
            ☰
          </button>
          <nav className={`topnav ${menuOpen ? 'open' : ''}`} aria-label="Main navigation">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={() => setMenuOpen(false)}
              >
                {item.label}
              </NavLink>
            ))}
            {user?.role === 'admin' && (
              <NavLink to="/admin" onClick={() => setMenuOpen(false)} className="admin-link">
                Admin
              </NavLink>
            )}
          </nav>
          <div className="topbar-user">
            <span className="user-chip" title={user?.email}>
              <span className="avatar" aria-hidden="true">{(user?.name || 'U').charAt(0).toUpperCase()}</span>
              <span className="user-name">{user?.name}</span>
            </span>
            <button type="button" className="btn btn-ghost btn-sm" onClick={handleLogout}>
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="content">
        <Outlet />
      </main>
      <footer className="footer">
        Enterprise Authentication &amp; Security · Sessions, alerts and audit trails are protected end-to-end.
      </footer>
    </div>
  );
}
