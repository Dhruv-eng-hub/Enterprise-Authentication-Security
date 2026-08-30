// API client — all requests go to the same origin (/api) through the Vite proxy
// so HttpOnly session cookies work without CORS issues.

// The server sets a JS-readable `authed` hint cookie alongside the HttpOnly
// session cookie. It carries no sensitive data — it only tells the SPA whether
// a session *might* exist, so anonymous visitors skip the /auth/me probe.
export const hasAuthHint = () => document.cookie.includes('authed=1');
export const clearAuthHint = () => {
  document.cookie = 'authed=; Max-Age=0; path=/';
};

async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    credentials: 'include',
    headers: options.body ? { 'Content-Type': 'application/json' } : undefined,
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  let data = null;
  let rawText = '';
  try {
    rawText = await res.text();
    data = JSON.parse(rawText);
  } catch {
    /* non-JSON response (e.g. CSV, or plain-text rate-limit message) */
  }

  if (!res.ok) {
    // Session expired or was revoked elsewhere — drop the stale hint so the
    // next page load doesn't probe again.
    if (res.status === 401) clearAuthHint();
    // Expired session while using a protected page → send the user to sign in
    // instead of showing a confusing error.
    if (res.status === 401 && data && data.message === 'You are not signed in. Please sign in again.' && !path.startsWith('/auth/')) {
      window.location.assign('/login');
    }
    const fallback = rawText && rawText.length < 200 && !rawText.includes('<')
      ? rawText
      : `Request failed (${res.status})`;
    const error = new Error((data && data.message) || fallback);
    error.status = res.status;
    error.data = data || {};
    throw error;
  }
  return data;
}

export const api = {
  get: (path) => request(path),
  post: (path, body) => request(path, { method: 'POST', body }),
  patch: (path, body) => request(path, { method: 'PATCH', body }),
  delete: (path) => request(path, { method: 'DELETE' })
};

// CSV export needs a blob download instead of JSON.
export async function downloadCsv(path, filename) {
  const res = await fetch(`/api${path}`, { credentials: 'include' });
  if (!res.ok) throw new Error('Export failed.');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function formatDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (sameDay) return `Today, ${time}`;
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return `Yesterday, ${time}`;
  return d.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' }) + `, ${time}`;
}

export function timeAgo(iso) {
  if (!iso) return '—';
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}
