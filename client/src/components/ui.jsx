import { useEffect } from 'react';

export function Card({ title, subtitle, actions, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-head">
          <div>
            {title && <h2 className="card-title">{title}</h2>}
            {subtitle && <p className="card-subtitle">{subtitle}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

const toneClass = { success: 'ok', warning: 'warn', critical: 'crit', info: 'info', error: 'crit' };

export function Badge({ tone = 'info', children }) {
  return <span className={`badge badge-${toneClass[tone] || 'info'}`}>{children}</span>;
}

export function Message({ kind = 'info', children, onDismiss }) {
  // Hide when there is nothing meaningful to show — including an array of
  // empty children like ['' , false], which would otherwise render an empty box.
  const list = Array.isArray(children) ? children : [children];
  const hasContent = list.some((c) => typeof c === 'string' ? c.trim() !== '' : Boolean(c));
  if (!hasContent) return null;
  return (
    <div className={`msg msg-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span>{children}</span>
      {onDismiss && (
        <button type="button" className="msg-close" aria-label="Dismiss" onClick={onDismiss}>×</button>
      )}
    </div>
  );
}

export function EmptyState({ icon = '🗂️', title, hint }) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">{icon}</span>
      <p className="empty-title">{title}</p>
      {hint && <p className="empty-hint">{hint}</p>}
    </div>
  );
}

export function ConfirmDialog({ open, title, body, confirmLabel = 'Confirm', danger = false, busy = false, onConfirm, onCancel }) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onCancel]);

  if (!open) return null;
  return (
    <div className="modal-backdrop" role="presentation" onClick={onCancel}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.stopPropagation()}>
        <h3>{title}</h3>
        <p>{body}</p>
        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`} onClick={onConfirm} disabled={busy}>
            {busy ? 'Working…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Pagination({ page, totalPages, onPage }) {
  if (totalPages <= 1) return null;
  return (
    <nav className="pagination" aria-label="Pagination">
      <button type="button" className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        ← Prev
      </button>
      <span className="pagination-info">Page {page} of {totalPages}</span>
      <button type="button" className="btn btn-ghost btn-sm" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>
        Next →
      </button>
    </nav>
  );
}

export function StatusPill({ status }) {
  const map = {
    SUCCESS: ['ok', '✓ Success'],
    FAILED: ['warn', '⚠ Failed'],
    LOCKED: ['crit', '🔒 Locked'],
    BLOCKED: ['crit', '⛔ Blocked'],
    SUSPICIOUS: ['crit', '⚠ Suspicious']
  };
  const [tone, label] = map[status] || ['info', status];
  return <Badge tone={tone}>{label}</Badge>;
}
