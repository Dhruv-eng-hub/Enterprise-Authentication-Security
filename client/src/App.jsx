import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from './AuthContext';
import Layout from './components/Layout';
import Spinner from './components/Spinner';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import VerifyEmailPage from './pages/VerifyEmailPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import HomePage from './pages/HomePage';
import SecurityDashboardPage from './pages/SecurityDashboardPage';
import ActivityPage from './pages/ActivityPage';
import SessionsPage from './pages/SessionsPage';
import AlertsPage from './pages/AlertsPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import TwoFactorPage from './pages/TwoFactorPage';
import AdminPage from './pages/AdminPage';

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <Spinner full label="Checking your session…" />;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function AdminOnly({ children }) {
  const { user } = useAuth();
  if (user?.role !== 'admin') return <Navigate to="/security" replace />;
  return children;
}

function Guest({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <Spinner full label="Loading…" />;
  if (user) return <Navigate to="/security" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      {/* Public (guest) pages */}
      <Route path="/login" element={<Guest><LoginPage /></Guest>} />
      <Route path="/register" element={<Guest><RegisterPage /></Guest>} />
      <Route path="/forgot-password" element={<Guest><ForgotPasswordPage /></Guest>} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/resend-verification" element={<VerifyEmailPage resendMode />} />

      {/* Protected app */}
      <Route element={<Protected><Layout /></Protected>}>
        <Route path="/" element={<HomePage />} />
        <Route path="/security" element={<SecurityDashboardPage />} />
        <Route path="/security/activity" element={<ActivityPage />} />
        <Route path="/security/sessions" element={<SessionsPage />} />
        <Route path="/security/alerts" element={<AlertsPage />} />
        <Route path="/security/password" element={<ChangePasswordPage />} />
        <Route path="/security/two-factor" element={<TwoFactorPage />} />
        <Route path="/admin" element={<AdminOnly><AdminPage /></AdminOnly>} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
