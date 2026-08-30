import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api, hasAuthHint, clearAuthHint } from './api';

const AuthContext = createContext(null);

// Single in-flight bootstrap request so React StrictMode's dev-time double
// mount doesn't fire /auth/me twice.
let bootstrapPromise = null;

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const data = await api.get('/auth/me');
      setUser(data.user);
      return data.user;
    } catch {
      setUser(null);
      return null;
    }
  }, []);

  useEffect(() => {
    // No hint cookie → no session to restore; skip the probe entirely so
    // anonymous page loads never hit /auth/me (and never log a 401).
    if (!hasAuthHint()) {
      setUser(null);
      setLoading(false);
      return;
    }
    if (!bootstrapPromise) {
      bootstrapPromise = refresh().finally(() => {
        setLoading(false);
        bootstrapPromise = null;
      });
    }
  }, [refresh]);

  const login = useCallback(async (email, password) => {
    const data = await api.post('/auth/login', { email, password });
    if (!data.requiresTwoFactor) await refresh();
    return data;
  }, [refresh]);

  const loginTwoFactor = useCallback(async (code) => {
    const data = await api.post('/auth/login/2fa', { code });
    await refresh();
    return data;
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout', {});
    } finally {
      clearAuthHint();
      setUser(null);
    }
  }, []);

  const signOutEverywhere = useCallback(async () => {
    await api.post('/security/sessions/logout-all', {});
    clearAuthHint();
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, refresh, login, loginTwoFactor, logout, signOutEverywhere }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
