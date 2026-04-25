import React, { useState } from 'react';

const ATTACK_OPTIONS = [
  { id: 'sql-injection', label: 'SQL Injection', icon: '💉' },
  { id: 'xss', label: 'XSS', icon: '📜' },
  { id: 'rate-limit', label: 'Rate Limit', icon: '⚡' },
  { id: 'header-security', label: 'Headers', icon: '🔒' },
  { id: 'auth-bypass', label: 'Auth Bypass', icon: '🔓' },
];

export default function ScanForm({ onSubmit, disabled }) {
  const [url, setUrl] = useState('');
  const [attacks, setAttacks] = useState(ATTACK_OPTIONS.map((a) => a.id));

  const toggleAttack = (id) => {
    setAttacks((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id],
    );
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    let finalUrl = url.trim();
    if (!finalUrl || attacks.length === 0) return;
    
    // Auto-prepend protocol if missing
    if (!/^https?:\/\//i.test(finalUrl)) {
      finalUrl = finalUrl.startsWith('localhost') || finalUrl.startsWith('127.0.0.1') 
        ? 'http://' + finalUrl 
        : 'https://' + finalUrl;
    }
    
    onSubmit(finalUrl, attacks);
  };

  return (
    <div className="card scan-form animate-in">
      <div className="card__title">
        <span className="card__title-icon">🎯</span>
        Target Configuration
      </div>

      <form onSubmit={handleSubmit}>
        <div className="scan-form__row">
          <div className="scan-form__input-wrap">
            <span className="scan-form__input-icon">🌐</span>
            <input
              id="target-url-input"
              className="scan-form__input"
              type="text"
              placeholder="https://your-api.com/api/endpoint"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={disabled}
              autoFocus
            />
          </div>
          <button
            id="start-scan-btn"
            className="scan-form__btn"
            type="submit"
            disabled={disabled || !url.trim() || attacks.length === 0}
          >
            🚀 Launch Scan
          </button>
        </div>

        <div className="attack-toggles">
          {ATTACK_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              type="button"
              className={`attack-toggle ${attacks.includes(opt.id) ? 'attack-toggle--active' : ''}`}
              onClick={() => toggleAttack(opt.id)}
              disabled={disabled}
            >
              {opt.icon} {opt.label}
            </button>
          ))}
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 8 }}>
          💡 Tip: Use <code style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>http://localhost:3002</code> (or <code style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>http://vulnerable-api:3002</code> if in Docker) to test against the built-in vulnerable API
        </div>
      </form>
    </div>
  );
}
