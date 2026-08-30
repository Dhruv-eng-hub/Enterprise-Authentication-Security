import { useCallback, useEffect, useState } from 'react';
import { api, downloadCsv, formatDateTime } from '../api';
import { Card, EmptyState, Pagination, StatusPill } from '../components/ui';
import Spinner from '../components/Spinner';

const STATUSES = ['', 'SUCCESS', 'FAILED', 'BLOCKED', 'LOCKED', 'SUSPICIOUS'];

export default function ActivityPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');

  const load = useCallback(() => {
    const params = new URLSearchParams({ page: String(page), limit: '10' });
    if (status) params.set('status', status);
    if (search) params.set('search', search);
    api.get(`/security/login-activity?${params}`)
      .then(setData)
      .catch((err) => setError(err.message));
  }, [page, status, search]);

  useEffect(() => { load(); }, [load]);

  const submitSearch = (e) => {
    e.preventDefault();
    setPage(1);
    setSearch(searchInput.trim());
  };

  const exportCsv = async () => {
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (search) params.set('search', search);
    await downloadCsv(
      `/security/login-activity/export?${params}`,
      `login-activity-${new Date().toISOString().slice(0, 10)}.csv`
    );
  };

  if (error) return <div className="card"><p>{error}</p></div>;

  return (
    <>
      <h1 className="page-title">Login Activity</h1>
      <p className="page-subtitle">Every sign-in attempt on your account, including failures and blocked access.</p>

      <Card>
        <div className="toolbar">
          <form className="grow" onSubmit={submitSearch} role="search">
            <input
              type="text" className="grow" style={{ width: '100%' }}
              placeholder="Search by browser, OS, device or IP…"
              value={searchInput} onChange={(e) => setSearchInput(e.target.value)}
              aria-label="Search login activity"
            />
          </form>
          <select
            value={status} aria-label="Filter by status"
            onChange={(e) => { setStatus(e.target.value); setPage(1); }}
          >
            {STATUSES.map((s) => <option key={s || 'all'} value={s}>{s ? s.charAt(0) + s.slice(1).toLowerCase() : 'All statuses'}</option>)}
          </select>
          <button type="button" className="btn btn-ghost btn-sm" onClick={exportCsv}>
            ⬇ Export CSV
          </button>
        </div>

        {!data ? (
          <Spinner label="Loading login history…" />
        ) : data.items.length === 0 ? (
          <EmptyState icon="🔍" title="No login activity found" hint="Try different filters, or sign in from a device to create history." />
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Device</th>
                  <th>IP address</th>
                  <th>When</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((row) => (
                  <tr key={row.id}>
                    <td><StatusPill status={row.status} /></td>
                    <td>
                      <div className="cell-main">{row.browser} • {row.os}</div>
                      <div className="cell-sub">{row.device}{row.location ? ` · ${row.location}` : ''}</div>
                    </td>
                    <td>{row.ip_address}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatDateTime(row.created_at)}</td>
                    <td className="cell-sub">{row.reason || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {data && <Pagination page={data.page} totalPages={data.totalPages} onPage={setPage} />}
        {data && <p className="cell-sub" style={{ textAlign: 'center', margin: '8px 0 0' }}>{data.total} event(s) total</p>}
      </Card>
    </>
  );
}
