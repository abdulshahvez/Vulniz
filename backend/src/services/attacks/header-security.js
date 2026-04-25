import httpClient from '../../utils/http-client.js';
import logger from '../../utils/logger.js';

/**
 * Header Security Check Module
 * ────────────────────────────
 * Inspects HTTP response headers for missing or misconfigured
 * security headers as recommended by OWASP.
 */

/** Expected headers and their ideal values / patterns */
const SECURITY_HEADERS = [
  {
    name: 'Strict-Transport-Security',
    description: 'HSTS — forces HTTPS connections',
    recommendation: "Set to 'max-age=31536000; includeSubDomains; preload'",
    severity: 'HIGH',
  },
  {
    name: 'Content-Security-Policy',
    description: 'CSP — prevents XSS and injection attacks',
    recommendation: "Define a strict CSP, e.g. \"default-src 'self'\"",
    severity: 'HIGH',
  },
  {
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME-type sniffing',
    expected: 'nosniff',
    recommendation: "Set to 'nosniff'",
    severity: 'MEDIUM',
  },
  {
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking',
    expected: /^(DENY|SAMEORIGIN)$/i,
    recommendation: "Set to 'DENY' or 'SAMEORIGIN'",
    severity: 'MEDIUM',
  },
  {
    name: 'X-XSS-Protection',
    description: 'Legacy XSS filter (still recommended for older browsers)',
    expected: /^1;\s*mode=block$/i,
    recommendation: "Set to '1; mode=block'",
    severity: 'LOW',
  },
  {
    name: 'Referrer-Policy',
    description: 'Controls referrer information sent with requests',
    recommendation: "Set to 'strict-origin-when-cross-origin' or 'no-referrer'",
    severity: 'LOW',
  },
  {
    name: 'Permissions-Policy',
    description: 'Controls browser feature access (camera, mic, geolocation, etc.)',
    recommendation: "Set to restrict unnecessary features, e.g. 'camera=(), microphone=()'",
    severity: 'LOW',
  },
  {
    name: 'Cache-Control',
    description: 'Controls caching of sensitive responses',
    recommendation: "Set to 'no-store, no-cache, must-revalidate' for sensitive endpoints",
    severity: 'LOW',
  },
];

/** Headers that should NOT be present (information leakage) */
const DANGEROUS_HEADERS = [
  {
    name: 'Server',
    description: 'Leaks server software information',
    recommendation: 'Remove or set to a generic value',
    severity: 'LOW',
  },
  {
    name: 'X-Powered-By',
    description: 'Leaks framework/runtime information',
    recommendation: 'Remove this header entirely',
    severity: 'LOW',
  },
  {
    name: 'X-AspNet-Version',
    description: 'Leaks ASP.NET version',
    recommendation: 'Remove this header entirely',
    severity: 'MEDIUM',
  },
];

/**
 * Run header security checks against the target.
 * @param {string} targetUrl
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export async function runHeaderSecurity(targetUrl, options = {}) {
  logger.info(`[Headers] Starting header security checks on ${targetUrl}`);

  const results = {
    attackType: 'header-security',
    targetUrl,
    totalChecks: SECURITY_HEADERS.length + DANGEROUS_HEADERS.length,
    findings: [],
    vulnerable: false,
    severity: 'NONE',
    startTime: Date.now(),
    endTime: null,
    headersPresent: {},
  };

  // ── Fetch the response ─────────────────────────────────────────────
  const res = await httpClient.get(targetUrl);
  const headers = res.headers || {};
  results.headersPresent = { ...headers };

  // ── Check for CORS misconfiguration ────────────────────────────────
  const corsRes = await httpClient.get(targetUrl, {
    headers: { Origin: 'https://evil-attacker-site.com' },
  });
  const allowOrigin = corsRes.headers?.['access-control-allow-origin'];
  const allowCreds = corsRes.headers?.['access-control-allow-credentials'];

  if (allowOrigin === '*') {
    results.findings.push({
      header: 'Access-Control-Allow-Origin',
      issue: 'CORS allows all origins (*)',
      value: allowOrigin,
      severity: 'HIGH',
      indicators: ['Wildcard CORS — any website can make authenticated requests'],
      recommendation: 'Restrict to specific trusted origins',
    });
  } else if (allowOrigin === 'https://evil-attacker-site.com') {
    results.findings.push({
      header: 'Access-Control-Allow-Origin',
      issue: 'CORS reflects arbitrary origins',
      value: allowOrigin,
      severity: 'HIGH',
      indicators: ['Origin reflection — server echoes back any Origin header'],
      recommendation: 'Validate origins against an allowlist',
    });
  }

  if (allowCreds === 'true' && (allowOrigin === '*' || allowOrigin === 'https://evil-attacker-site.com')) {
    results.findings.push({
      header: 'Access-Control-Allow-Credentials',
      issue: 'Credentials allowed with permissive CORS',
      value: 'true',
      severity: 'HIGH',
      indicators: ['Credentials + open CORS = full account takeover risk'],
      recommendation: 'Never combine Access-Control-Allow-Credentials with wildcard or reflected origins',
    });
  }

  // ── Check missing security headers ─────────────────────────────────
  for (const hdr of SECURITY_HEADERS) {
    const headerValue = headers[hdr.name.toLowerCase()];

    if (!headerValue) {
      results.findings.push({
        header: hdr.name,
        issue: `Missing security header: ${hdr.name}`,
        description: hdr.description,
        severity: hdr.severity,
        indicators: [`${hdr.name} header is not set`],
        recommendation: hdr.recommendation,
      });
    } else if (hdr.expected) {
      const matches =
        hdr.expected instanceof RegExp
          ? hdr.expected.test(headerValue)
          : headerValue.toLowerCase() === hdr.expected.toLowerCase();

      if (!matches) {
        results.findings.push({
          header: hdr.name,
          issue: `Misconfigured: ${hdr.name}`,
          value: headerValue,
          severity: hdr.severity,
          indicators: [`${hdr.name} has unexpected value: "${headerValue}"`],
          recommendation: hdr.recommendation,
        });
      }
    }
  }

  // ── Check for information-leaking headers ──────────────────────────
  for (const hdr of DANGEROUS_HEADERS) {
    const headerValue = headers[hdr.name.toLowerCase()];
    if (headerValue) {
      results.findings.push({
        header: hdr.name,
        issue: `Information leakage: ${hdr.name}`,
        value: headerValue,
        description: hdr.description,
        severity: hdr.severity,
        indicators: [`${hdr.name} header exposes: "${headerValue}"`],
        recommendation: hdr.recommendation,
      });
    }
  }

  // ── Severity assessment ────────────────────────────────────────────
  results.vulnerable = results.findings.length > 0;
  const highCount = results.findings.filter((f) => f.severity === 'HIGH').length;
  const medCount = results.findings.filter((f) => f.severity === 'MEDIUM').length;

  if (highCount >= 2) {
    results.severity = 'HIGH';
  } else if (highCount >= 1 || medCount >= 3) {
    results.severity = 'MEDIUM';
  } else if (results.findings.length >= 1) {
    results.severity = 'LOW';
  }

  results.endTime = Date.now();
  results.durationMs = results.endTime - results.startTime;
  logger.info(`[Headers] Completed — ${results.findings.length} finding(s), severity: ${results.severity}`);

  return results;
}
