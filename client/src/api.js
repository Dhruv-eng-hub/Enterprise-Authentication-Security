const API_BASE_URL =
  import.meta.env.VITE_API_URL ||
  'https://enterprise-authentication-security.onrender.com';

// ------------------------------------------------------------
// Authentication hint
// ------------------------------------------------------------

export const hasAuthHint = () =>
  document.cookie.includes('authed=1');

export const clearAuthHint = () => {
  document.cookie = 'authed=; Max-Age=0; path=/';
};

// ------------------------------------------------------------
// Date/time helpers
// ------------------------------------------------------------

export const formatDateTime = (value) => {
  if (!value) return '—';

  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
};

export const timeAgo = (value) => {
  if (!value) return '—';

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  const seconds = Math.floor(
    (Date.now() - date.getTime()) / 1000
  );

  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;

  const years = Math.floor(months / 12);
  return `${years}y ago`;
};

// ------------------------------------------------------------
// API request
// ------------------------------------------------------------

async function request(path, options = {}) {
  const fetchOptions = {
    credentials: 'include',
    ...options,
    headers: {
      ...(options.body
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...(options.headers || {})
    }
  };

  if (options.body !== undefined) {
    fetchOptions.body =
      typeof options.body === 'string'
        ? options.body
        : JSON.stringify(options.body);
  }

  const res = await fetch(
    `${API_BASE_URL}/api${path}`,
    fetchOptions
  );

  let data = null;
  let rawText = '';

  try {
    rawText = await res.text();

    if (rawText) {
      data = JSON.parse(rawText);
    }
  } catch {
    // Response was not JSON
  }

  if (!res.ok) {
    if (res.status === 401) {
      clearAuthHint();
    }

    if (
      res.status === 401 &&
      data &&
      data.message ===
        'You are not signed in. Please sign in again.' &&
      !path.startsWith('/auth/')
    ) {
      window.location.assign('/login');
    }

    const fallback =
      rawText &&
      rawText.length < 200 &&
      !rawText.includes('<')
        ? rawText
        : `Request failed (${res.status})`;

    const error = new Error(
      (data && data.message) || fallback
    );

    error.status = res.status;
    error.data = data || {};

    throw error;
  }

  return data;
}

// ------------------------------------------------------------
// API methods
// ------------------------------------------------------------

export const api = {
  get: (path) =>
    request(path),

  post: (path, body) =>
    request(path, {
      method: 'POST',
      body
    }),

  patch: (path, body) =>
    request(path, {
      method: 'PATCH',
      body
    }),

  delete: (path) =>
    request(path, {
      method: 'DELETE'
    })
};

// ------------------------------------------------------------
// CSV download
// ------------------------------------------------------------

export async function downloadCsv(
  path,
  filename = 'export.csv'
) {
  const res = await fetch(
    `${API_BASE_URL}/api${path}`,
    {
      credentials: 'include'
    }
  );

  if (!res.ok) {
    let message = `Request failed (${res.status})`;

    try {
      const data = await res.json();
      message = data.message || message;
    } catch {
      // Ignore non-JSON error response
    }

    throw new Error(message);
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;

  document.body.appendChild(a);
  a.click();
  a.remove();

  URL.revokeObjectURL(url);
}
