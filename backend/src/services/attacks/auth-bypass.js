import httpClient from '../../utils/http-client.js';
import logger from '../../utils/logger.js';

/**
 * Authentication Bypass Attack Module
 * ────────────────────────────────────
 * Tests for common authentication weaknesses:
 *  - Missing auth on endpoints
 *  - JWT tampering (alg=none, signature removal)
 *  - Token replay / predictable tokens
 *  - Insecure direct object references (IDOR-style)
 */

const TAMPERED_TOKENS = [
  // JWT with alg:none
  'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjk5MDAwMDAwfQ.',
  // JWT with modified role
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjk5MDAwMDAwfQ.invalid-signature',
  // Empty token
  '',
  // Null-byte
  '\x00',
  // "undefined" / "null" strings
  'undefined',
  'null',
  // Random garbage
  'aaaa.bbbb.cccc',
  // Admin cookie
  'admin=true',
  'role=admin',
  'isAdmin=1',
];

const AUTH_HEADERS_TO_TEST = [
  'Authorization',
  'X-Auth-Token',
  'X-API-Key',
  'Cookie',
  'X-Access-Token',
];

/**
 * Run authentication bypass tests against the target.
 * @param {string} targetUrl
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export async function runAuthBypass(targetUrl, options = {}) {
  logger.info(`[AuthBypass] Starting authentication bypass tests on ${targetUrl}`);

  const results = {
    attackType: 'auth-bypass',
    targetUrl,
    totalPayloads: TAMPERED_TOKENS.length * AUTH_HEADERS_TO_TEST.length + 5,
    findings: [],
    vulnerable: false,
    severity: 'NONE',
    startTime: Date.now(),
    endTime: null,
  };

  // ── 1. Baseline — request with no authentication ───────────────────
  const noAuthRes = await httpClient.get(targetUrl);
  const noAuthBody = JSON.stringify(noAuthRes.data || '');

  // If the endpoint returns 200 with data without any auth, it might be unprotected
  if (noAuthRes.status === 200 && noAuthBody.length > 50) {
    // Check if it looks like it should be protected (contains sensitive data patterns)
    const sensitivePatterns = [
      'email', 'password', 'secret', 'token', 'apikey', 'api_key',
      'credit', 'ssn', 'phone', 'address', 'salary',
    ];
    const bodyLower = noAuthBody.toLowerCase();
    const leakedFields = sensitivePatterns.filter((p) => bodyLower.includes(p));

    if (leakedFields.length > 0) {
      results.findings.push({
        test: 'no-auth-access',
        description: 'Endpoint accessible without authentication — contains sensitive data',
        statusCode: noAuthRes.status,
        leakedFields,
        indicators: [
          'Endpoint returns sensitive data without requiring authentication',
          `Potential data leakage: ${leakedFields.join(', ')}`,
        ],
        responseSnippet: noAuthBody.substring(0, 500),
      });
    }
  }

  // ── 2. Token tampering ─────────────────────────────────────────────
  for (const header of AUTH_HEADERS_TO_TEST) {
    for (const token of TAMPERED_TOKENS) {
      try {
        const headerValue = header === 'Authorization' ? `Bearer ${token}` : token;
        const res = await httpClient.get(targetUrl, {
          headers: { [header]: headerValue },
        });

        // Successful response with tampered token = vulnerability
        if (res.status === 200) {
          const body = JSON.stringify(res.data || '');
          // Only flag if the response looks like it contains actual data
          if (body.length > noAuthBody.length || body.includes('admin') || body.includes('user')) {
            results.findings.push({
              test: 'token-tampering',
              description: `Tampered token accepted via ${header}`,
              header,
              token: token.substring(0, 50) + (token.length > 50 ? '…' : ''),
              statusCode: res.status,
              indicators: [
                `Server accepted tampered/invalid ${header} header`,
                'Possible JWT validation bypass or missing token verification',
              ],
              responseSnippet: body.substring(0, 300),
            });
          }
        }
      } catch (err) {
        // Errors are expected for garbage tokens
      }
    }
  }

  // ── 3. Method-based bypass ─────────────────────────────────────────
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
  for (const method of methods) {
    try {
      const res = await httpClient.request({
        method: method.toLowerCase(),
        url: targetUrl,
      });

      // If a typically-restricted method returns 200 with data
      if (['PUT', 'DELETE', 'PATCH'].includes(method) && res.status === 200) {
        results.findings.push({
          test: 'method-bypass',
          description: `${method} request succeeded without authentication`,
          method,
          statusCode: res.status,
          indicators: [
            `${method} method accessible without authentication`,
            'Missing method-level authorization checks',
          ],
        });
      }
    } catch {
      // Expected for unsupported methods
    }
  }

  // ── 4. Path traversal / IDOR ───────────────────────────────────────
  const idorPaths = ['/1', '/2', '/0', '/-1', '/999999', '/admin', '/../../etc/passwd'];
  for (const path of idorPaths) {
    try {
      const idorUrl = targetUrl.replace(/\/$/, '') + path;
      const res = await httpClient.get(idorUrl);

      if (res.status === 200 && JSON.stringify(res.data || '').length > 20) {
        results.findings.push({
          test: 'idor',
          description: `Accessible resource at ${path} without authorization`,
          path,
          url: idorUrl,
          statusCode: res.status,
          indicators: ['Possible Insecure Direct Object Reference (IDOR)'],
          responseSnippet: JSON.stringify(res.data).substring(0, 300),
        });
      }
    } catch {
      // Expected for invalid paths
    }
  }

  // ── Severity ───────────────────────────────────────────────────────
  results.vulnerable = results.findings.length > 0;
  const hasTokenBypass = results.findings.some((f) => f.test === 'token-tampering');
  const hasNoAuth = results.findings.some((f) => f.test === 'no-auth-access');

  if (hasTokenBypass || hasNoAuth) {
    results.severity = 'HIGH';
  } else if (results.findings.length >= 3) {
    results.severity = 'MEDIUM';
  } else if (results.findings.length >= 1) {
    results.severity = 'LOW';
  }

  results.endTime = Date.now();
  results.durationMs = results.endTime - results.startTime;
  logger.info(`[AuthBypass] Completed — ${results.findings.length} finding(s), severity: ${results.severity}`);

  return results;
}
