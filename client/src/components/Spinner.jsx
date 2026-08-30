export default function Spinner({ full = false, label = 'Loading…' }) {
  const spinner = (
    <div className="spinner-wrap" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span className="spinner-label">{label}</span>
    </div>
  );
  return full ? <div className="spinner-full">{spinner}</div> : spinner;
}
