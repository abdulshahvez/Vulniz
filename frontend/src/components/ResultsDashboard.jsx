import React from 'react';
import ScoreGauge from './ScoreGauge.jsx';
import VulnerabilityCard from './VulnerabilityCard.jsx';
import { getPdfUrl } from '../services/api.js';

/**
 * Full results dashboard — score, breakdown, vulns, fixes.
 */
export default function ResultsDashboard({ results, scanId, onReset }) {
  const { score, analysis, fixes, results: attackResults } = results;

  const vulnerableResults = (attackResults || []).filter(
    (r) => r.vulnerable && r.findings?.length > 0,
  );

  return (
    <div className="results animate-in">
      {/* ── Scan Summary Header ──────────────────────────── */}
      <div className="card" style={{ marginBottom: '1.5rem', borderLeft: '4px solid var(--accent)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ fontSize: '1.5rem' }}>🌐</div>
          <div>
            <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '4px' }}>
              Scanned Endpoint
            </div>
            <div style={{ fontSize: '1.1rem', fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
              {results.targetUrl}
            </div>
          </div>
        </div>
      </div>

      {/* ── Top: Score + Breakdown ─────────────────────────── */}
      <div className="results__top">
        <div className="card">
          <ScoreGauge
            score={score?.score ?? 0}
            riskLevel={score?.riskLevel ?? ''}
            riskColor={score?.riskColor ?? '#00d4ff'}
          />
        </div>

        <div className="card">
          <div className="card__title">
            <span className="card__title-icon">📊</span>
            Vulnerability Breakdown
          </div>

          <div className="breakdown">
            <div className="breakdown__item breakdown__item--critical">
              <div className="breakdown__count">{score?.breakdown?.critical ?? 0}</div>
              <div className="breakdown__label">Critical</div>
            </div>
            <div className="breakdown__item breakdown__item--high">
              <div className="breakdown__count">{score?.breakdown?.high ?? 0}</div>
              <div className="breakdown__label">High</div>
            </div>
            <div className="breakdown__item breakdown__item--medium">
              <div className="breakdown__count">{score?.breakdown?.medium ?? 0}</div>
              <div className="breakdown__label">Medium</div>
            </div>
            <div className="breakdown__item breakdown__item--low">
              <div className="breakdown__count">{score?.breakdown?.low ?? 0}</div>
              <div className="breakdown__label">Low</div>
            </div>
          </div>

          <div style={{ marginTop: 20, fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {score?.riskDescription}
          </div>

          <div className="actions">
            <button className="btn btn--primary" onClick={onReset}>
              🔄 New Scan
            </button>
            <a className="btn" href={getPdfUrl(scanId)} target="_blank" rel="noreferrer">
              📄 Download PDF
            </a>
          </div>
        </div>
      </div>

      {/* ── Vulnerabilities ────────────────────────────────── */}
      {vulnerableResults.length > 0 && (
        <div>
          <div className="results__section-title">
            <span>⚠</span> Detected Vulnerabilities ({vulnerableResults.length})
          </div>
          <div className="results__vulns">
            {vulnerableResults
              .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))
              .map((r, i) => (
                <VulnerabilityCard key={i} result={r} />
              ))}
          </div>
        </div>
      )}

      {vulnerableResults.length === 0 && (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state__icon">🎉</div>
            <div className="empty-state__title">No Vulnerabilities Detected</div>
            <div className="empty-state__desc">
              Great job! The scanned endpoint appears to be well-secured against the tested attack vectors.
            </div>
          </div>
        </div>
      )}

      {/* ── Recommendations ────────────────────────────────── */}
      {score?.recommendations?.length > 0 && (
        <div>
          <div className="results__section-title">
            <span>📋</span> Recommendations
          </div>
          <div className="results__vulns">
            {score.recommendations.map((rec, i) => (
              <div className="card animate-in" key={i}>
                <div style={{ fontWeight: 600, fontSize: '0.95rem', marginBottom: 6 }}>
                  {rec.priority}. {rec.title}
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
                  {rec.description}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--accent)' }}>
                  OWASP: {rec.owasp}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Fix Suggestions ────────────────────────────────── */}
      {fixes && Object.keys(fixes).length > 0 && (
        <div>
          <div className="results__section-title">
            <span>🤖</span> Fix Suggestions
          </div>
          <div className="results__vulns">
            {Object.entries(fixes).map(([type, fix]) => (
              <div className="fix-card animate-in" key={type}>
                <div className="fix-card__title">{fix.title}</div>
                <div className="fix-card__desc">{fix.description}</div>
                {fix.codeSnippet && (
                  <div className="fix-card__code">{fix.codeSnippet}</div>
                )}
                {fix.bestPractices && (
                  <ul className="fix-card__practices">
                    {fix.bestPractices.map((bp, i) => (
                      <li key={i}>{bp}</li>
                    ))}
                  </ul>
                )}
                {fix.owaspRef && (
                  <a className="fix-card__owasp" href={fix.owaspRef} target="_blank" rel="noreferrer">
                    📖 OWASP Reference →
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function severityOrder(s) {
  return { HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 }[s] || 0;
}
