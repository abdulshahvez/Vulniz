import logger from '../utils/logger.js';

/**
 * Security Scoring Service
 * ────────────────────────
 * Generates a security score (0-100) based on the analysis results.
 * Higher score = more secure.
 *
 * Scoring methodology:
 *  - Start with 100 points
 *  - Deduct points based on severity and count of findings
 *  - Weight: CRITICAL -25, HIGH -15, MEDIUM -8, LOW -3
 *  - Minimum score is 0
 */

const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
};

const RISK_LEVELS = [
  { min: 90, level: 'EXCELLENT', color: '#00ff88', description: 'Your API security is excellent.' },
  { min: 75, level: 'GOOD', color: '#88ff00', description: 'Good security posture with minor improvements needed.' },
  { min: 50, level: 'MODERATE', color: '#ffaa00', description: 'Moderate risk — several vulnerabilities need attention.' },
  { min: 25, level: 'POOR', color: '#ff6600', description: 'Poor security — significant vulnerabilities detected.' },
  { min: 0, level: 'CRITICAL', color: '#ff0044', description: 'Critical risk — immediate remediation required.' },
];

/**
 * Calculate the security score from analysis results.
 *
 * @param {object} analysis - Output from analyzeResults()
 * @returns {object} - Score report with score, risk level, and breakdown
 */
export function calculateScore(analysis) {
  logger.info('[Scoring] Calculating security score…');

  let score = 100;
  const deductions = [];

  // Deduct for critical findings
  for (const finding of analysis.criticalFindings || []) {
    const deduction = SEVERITY_WEIGHTS.CRITICAL;
    score -= deduction;
    deductions.push({
      reason: finding.description || finding.issue || `Critical vulnerability in ${finding.attackType}`,
      severity: 'CRITICAL',
      points: deduction,
    });
  }

  // Deduct for high findings (excluding those already counted as critical)
  const criticalSet = new Set((analysis.criticalFindings || []).map((f) => JSON.stringify(f)));
  for (const finding of analysis.highFindings || []) {
    if (criticalSet.has(JSON.stringify(finding))) continue;
    const deduction = SEVERITY_WEIGHTS.HIGH;
    score -= deduction;
    deductions.push({
      reason: finding.description || finding.issue || `High-severity issue in ${finding.attackType}`,
      severity: 'HIGH',
      points: deduction,
    });
  }

  // Medium findings
  for (const finding of analysis.mediumFindings || []) {
    const deduction = SEVERITY_WEIGHTS.MEDIUM;
    score -= deduction;
    deductions.push({
      reason: finding.description || finding.issue || `Medium-severity issue in ${finding.attackType}`,
      severity: 'MEDIUM',
      points: deduction,
    });
  }

  // Low findings
  for (const finding of analysis.lowFindings || []) {
    const deduction = SEVERITY_WEIGHTS.LOW;
    score -= deduction;
    deductions.push({
      reason: finding.description || finding.issue || `Low-severity issue in ${finding.attackType}`,
      severity: 'LOW',
      points: deduction,
    });
  }

  // Clamp to [0, 100]
  score = Math.max(0, Math.min(100, score));

  // Determine risk level
  const riskLevel = RISK_LEVELS.find((r) => score >= r.min) || RISK_LEVELS[RISK_LEVELS.length - 1];

  const report = {
    score: Math.round(score),
    maxScore: 100,
    riskLevel: riskLevel.level,
    riskColor: riskLevel.color,
    riskDescription: riskLevel.description,
    deductions,
    breakdown: {
      critical: (analysis.criticalFindings || []).length,
      high: (analysis.highFindings || []).length,
      medium: (analysis.mediumFindings || []).length,
      low: (analysis.lowFindings || []).length,
      total: analysis.totalFindings || 0,
    },
    recommendations: generateRecommendations(analysis),
  };

  logger.info(`[Scoring] Score: ${report.score}/100 — Risk: ${report.riskLevel}`);
  return report;
}

/**
 * Generate prioritized recommendations based on findings.
 */
function generateRecommendations(analysis) {
  const recs = [];

  const attackTypes = new Set([
    ...(analysis.highFindings || []).map((f) => f.attackType),
    ...(analysis.criticalFindings || []).map((f) => f.attackType),
    ...(analysis.mediumFindings || []).map((f) => f.attackType),
  ]);

  if (attackTypes.has('sql-injection')) {
    recs.push({
      priority: 1,
      title: 'Fix SQL Injection Vulnerabilities',
      description: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.',
      owasp: 'A03:2021 – Injection',
    });
  }

  if (attackTypes.has('xss')) {
    recs.push({
      priority: 2,
      title: 'Fix Cross-Site Scripting (XSS)',
      description: 'Sanitize and encode all user input before reflecting it in responses. Implement Content-Security-Policy headers.',
      owasp: 'A03:2021 – Injection',
    });
  }

  if (attackTypes.has('auth-bypass')) {
    recs.push({
      priority: 1,
      title: 'Strengthen Authentication',
      description: 'Validate JWT signatures server-side. Implement proper session management and token expiration.',
      owasp: 'A07:2021 – Identification and Authentication Failures',
    });
  }

  if (attackTypes.has('rate-limit')) {
    recs.push({
      priority: 3,
      title: 'Implement Rate Limiting',
      description: 'Add rate limiting to all endpoints, especially authentication endpoints. Consider using token bucket or sliding window algorithms.',
      owasp: 'A04:2021 – Insecure Design',
    });
  }

  if (attackTypes.has('header-security')) {
    recs.push({
      priority: 4,
      title: 'Configure Security Headers',
      description: 'Add HSTS, CSP, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy headers.',
      owasp: 'A05:2021 – Security Misconfiguration',
    });
  }

  return recs.sort((a, b) => a.priority - b.priority);
}
