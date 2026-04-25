import logger from '../utils/logger.js';

/**
 * Analysis Engine
 * ───────────────
 * Compares baseline (normal) responses with attack responses to detect
 * anomalies: unexpected successes, data leakage, timing differences, etc.
 */

/**
 * Analyze the raw results from all attack modules and produce a
 * structured analysis report.
 *
 * @param {object[]} attackResults - Array of results from each attack module
 * @returns {object} - Analyzed report with anomalies and categorized findings
 */
export function analyzeResults(attackResults) {
  logger.info('[Analysis] Starting result analysis…');

  const analysis = {
    totalAttackTypes: attackResults.length,
    totalFindings: 0,
    criticalFindings: [],
    highFindings: [],
    mediumFindings: [],
    lowFindings: [],
    anomalies: [],
    summary: '',
    analyzedAt: new Date().toISOString(),
  };

  for (const result of attackResults) {
    const findings = result.findings || [];
    analysis.totalFindings += findings.length;

    // Categorize each finding
    for (const finding of findings) {
      const categorized = {
        attackType: result.attackType,
        ...finding,
        severity: finding.severity || result.severity,
      };

      switch (categorized.severity) {
        case 'HIGH':
          analysis.highFindings.push(categorized);
          break;
        case 'MEDIUM':
          analysis.mediumFindings.push(categorized);
          break;
        case 'LOW':
          analysis.lowFindings.push(categorized);
          break;
        default:
          analysis.lowFindings.push(categorized);
      }
    }

    // Detect anomalies
    if (result.vulnerable) {
      analysis.anomalies.push({
        attackType: result.attackType,
        severity: result.severity,
        findingCount: findings.length,
        description: getAnomalyDescription(result),
      });
    }
  }

  // Critical = HIGH findings with confirmed exploitation indicators
  analysis.criticalFindings = analysis.highFindings.filter((f) => {
    const indicators = f.indicators || [];
    return indicators.some(
      (i) =>
        i.includes('verbatim') ||
        i.includes('bypass') ||
        i.includes('credentials accepted') ||
        i.includes('data leakage') ||
        i.includes('account takeover'),
    );
  });

  // Build summary
  analysis.summary = buildSummary(analysis);

  logger.info(
    `[Analysis] Complete — ${analysis.totalFindings} findings (${analysis.criticalFindings.length} critical, ${analysis.highFindings.length} high, ${analysis.mediumFindings.length} medium, ${analysis.lowFindings.length} low)`,
  );

  return analysis;
}

/**
 * Generate a human-readable anomaly description.
 */
function getAnomalyDescription(result) {
  const descriptions = {
    'sql-injection': 'SQL injection payloads triggered unexpected database responses',
    'xss': 'XSS payloads were reflected without proper sanitization',
    'rate-limit': 'Rate limiting mechanisms are absent or insufficient',
    'header-security': 'Security headers are missing or misconfigured',
    'auth-bypass': 'Authentication mechanisms can be bypassed',
  };
  return descriptions[result.attackType] || `Vulnerability detected in ${result.attackType}`;
}

/**
 * Build a plain-text summary of the analysis.
 */
function buildSummary(analysis) {
  const parts = [];
  parts.push(`Found ${analysis.totalFindings} potential vulnerabilit${analysis.totalFindings === 1 ? 'y' : 'ies'} across ${analysis.totalAttackTypes} attack categories.`);

  if (analysis.criticalFindings.length > 0) {
    parts.push(`⚠ ${analysis.criticalFindings.length} CRITICAL issue(s) require immediate attention.`);
  }
  if (analysis.highFindings.length > 0) {
    parts.push(`${analysis.highFindings.length} HIGH severity issue(s) found.`);
  }
  if (analysis.mediumFindings.length > 0) {
    parts.push(`${analysis.mediumFindings.length} MEDIUM severity issue(s) found.`);
  }
  if (analysis.lowFindings.length > 0) {
    parts.push(`${analysis.lowFindings.length} LOW severity issue(s) found.`);
  }
  if (analysis.totalFindings === 0) {
    parts.push('No vulnerabilities detected. The API appears well-secured.');
  }

  return parts.join(' ');
}
