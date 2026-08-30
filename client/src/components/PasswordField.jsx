import { useMemo, useState } from 'react';

// Client-side mirror of the server password policy — instant feedback while typing.
const RULES = [
  { key: 'length', label: 'At least 8 characters', test: (pw) => pw.length >= 8 },
  { key: 'upper', label: 'One uppercase letter (A–Z)', test: (pw) => /[A-Z]/.test(pw) },
  { key: 'lower', label: 'One lowercase letter (a–z)', test: (pw) => /[a-z]/.test(pw) },
  { key: 'number', label: 'One number (0–9)', test: (pw) => /[0-9]/.test(pw) },
  { key: 'special', label: 'One special character (!@#$%…)', test: (pw) => /[^A-Za-z0-9\s]/.test(pw) }
];

const COMMON = new Set(['password', 'password123', 'qwerty', '123456', 'letmein', 'welcome', 'admin123', 'iloveyou']);

export function scorePassword(pw) {
  if (!pw) return { score: 0, label: 'none' };
  let points = 0;
  if (pw.length >= 8) points += 1;
  if (pw.length >= 12) points += 1;
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((rx) => rx.test(pw)).length;
  points += classes >= 3 ? 1 : 0;
  points += classes === 4 ? 1 : 0;
  if (COMMON.has(pw.toLowerCase().replace(/[^a-z0-9]/g, ''))) points = Math.min(points, 1);
  const capped = Math.max(0, Math.min(4, points));
  return { score: capped, label: ['weak', 'weak', 'fair', 'good', 'strong'][capped] };
}

export default function PasswordField({
  id, label, value, onChange, autoComplete = 'current-password',
  showStrength = false, placeholder = '', required = true
}) {
  const [visible, setVisible] = useState(false);
  const { score, label: strengthLabel } = useMemo(() => scorePassword(value), [value]);
  const rules = useMemo(() => RULES.map((r) => ({ ...r, met: r.test(value) })), [value]);

  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="password-wrap">
        <input
          id={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          placeholder={placeholder}
          required={required}
        />
        <button
          type="button"
          className="pw-toggle"
          aria-label={visible ? 'Hide password' : 'Show password'}
          onClick={() => setVisible((v) => !v)}
        >
          {visible ? '🙈' : '👁️'}
        </button>
      </div>

      {showStrength && value && (
        <div className="pw-strength" aria-live="polite">
          <div className="pw-strength-bars" aria-hidden="true">
            {[1, 2, 3, 4].map((i) => (
              <span key={i} className={`bar s-${strengthLabel} ${i <= score ? 'on' : ''}`} />
            ))}
          </div>
          <span className={`pw-strength-label s-${strengthLabel}`}>
            {strengthLabel === 'none' ? '' : strengthLabel.charAt(0).toUpperCase() + strengthLabel.slice(1)}
          </span>
        </div>
      )}

      {showStrength && (
        <ul className="pw-rules">
          {rules.map((r) => (
            <li key={r.key} className={r.met ? 'met' : ''}>
              <span aria-hidden="true">{r.met ? '✓' : '•'}</span> {r.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
