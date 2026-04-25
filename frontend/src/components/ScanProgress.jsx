import React, { useRef, useEffect } from 'react';

export default function ScanProgress({ progress, currentAttack, logs }) {
  const logEndRef = useRef(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const formatTime = (ts) => {
    try {
      return new Date(ts).toLocaleTimeString();
    } catch {
      return '';
    }
  };

  return (
    <div className="card progress-panel animate-in">
      <div className="card__title">
        <span className="card__title-icon pulse">⚙</span>
        Scan In Progress
      </div>

      <div className="progress-info">
        <div className="progress-percent">{progress}%</div>
        <div className="progress-status">
          {currentAttack
            ? `Running: ${currentAttack.toUpperCase()}`
            : progress >= 100
              ? 'Finalizing…'
              : 'Initializing…'}
        </div>
      </div>

      <div className="progress-bar-wrap">
        <div className="progress-bar" style={{ width: `${progress}%` }} />
      </div>

      <div className="log-console" id="scan-log-console">
        {logs.map((entry, i) => (
          <div className="log-entry" key={i}>
            <span className="log-entry__time">{formatTime(entry.timestamp)}</span>
            {entry.message}
          </div>
        ))}
        <div ref={logEndRef} />
      </div>
    </div>
  );
}
