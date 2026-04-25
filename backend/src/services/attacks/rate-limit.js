import httpClient from '../../utils/http-client.js';
import logger from '../../utils/logger.js';

/**
 * Rate Limiting / Brute-Force Simulation Module
 * ──────────────────────────────────────────────
 * Sends a burst of rapid requests to detect whether the target
 * enforces rate limiting. An unprotected API is vulnerable to
 * brute-force and denial-of-service attacks.
 */

const BURST_SIZE = 30; // number of rapid requests to send
const BRUTE_FORCE_CREDENTIALS = [
  { username: 'admin', password: 'admin' },
  { username: 'admin', password: 'password' },
  { username: 'admin', password: '123456' },
  { username: 'admin', password: 'admin123' },
  { username: 'root', password: 'root' },
  { username: 'test', password: 'test' },
  { username: 'user', password: 'user' },
  { username: 'admin', password: 'letmein' },
  { username: 'admin', password: 'welcome' },
  { username: 'admin', password: 'password123' },
];

/**
 * Run rate-limit & brute-force detection.
 * @param {string} targetUrl
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export async function runRateLimit(targetUrl, options = {}) {
  logger.info(`[RateLimit] Starting rate-limit tests on ${targetUrl}`);

  const results = {
    attackType: 'rate-limit',
    targetUrl,
    totalPayloads: BURST_SIZE + BRUTE_FORCE_CREDENTIALS.length,
    findings: [],
    vulnerable: false,
    severity: 'NONE',
    startTime: Date.now(),
    endTime: null,
  };

  // ── 1. Burst test — fire many requests in parallel ─────────────────
  logger.debug(`[RateLimit] Sending ${BURST_SIZE} rapid requests…`);
  const burstPromises = Array.from({ length: BURST_SIZE }, (_, i) =>
    httpClient.get(targetUrl, {
      headers: { 'X-Burst-Sequence': `${i + 1}` },
    }),
  );

  const burstResponses = await Promise.allSettled(burstPromises);
  const burstResults = burstResponses.map((r) =>
    r.status === 'fulfilled' ? r.value : { status: 0, error: true },
  );

  const statusCodes = burstResults.map((r) => r.status);
  const rateLimited = statusCodes.filter((s) => s === 429);
  const successCount = statusCodes.filter((s) => s >= 200 && s < 300);

  if (rateLimited.length === 0 && successCount.length === BURST_SIZE) {
    results.findings.push({
      test: 'burst-request',
      description: `All ${BURST_SIZE} rapid requests succeeded without rate limiting`,
      requestCount: BURST_SIZE,
      successCount: successCount.length,
      rateLimitedCount: 0,
      indicators: ['No rate limiting detected — vulnerable to brute force and DoS'],
      statusCodes: [...new Set(statusCodes)],
    });
  } else if (rateLimited.length > 0) {
    logger.info(`[RateLimit] Rate limiting detected after ${successCount.length} requests`);
  }

  // ── 2. Brute-force credential stuffing test ────────────────────────
  logger.debug('[RateLimit] Running brute-force credential test…');
  let bruteForceBlocked = false;

  for (const cred of BRUTE_FORCE_CREDENTIALS) {
    try {
      const res = await httpClient.post(targetUrl, cred);

      if (res.status === 429) {
        bruteForceBlocked = true;
        break;
      }

      // Check if any default cred actually worked
      if (res.status === 200) {
        const body = JSON.stringify(res.data || '').toLowerCase();
        if (body.includes('token') || body.includes('session') || body.includes('success')) {
          results.findings.push({
            test: 'brute-force',
            description: `Default credentials accepted: ${cred.username}/${cred.password}`,
            credentials: cred,
            statusCode: res.status,
            indicators: [
              'Default/weak credentials accepted',
              'No account lockout detected',
            ],
            responseSnippet: JSON.stringify(res.data).substring(0, 300),
          });
        }
      }
    } catch (err) {
      logger.warn(`[RateLimit] Brute-force request failed: ${err.message}`);
    }
  }

  if (!bruteForceBlocked && results.findings.length === 0) {
    results.findings.push({
      test: 'brute-force',
      description: 'No account lockout or rate limiting on login endpoint',
      indicators: ['API did not block repeated login attempts'],
      credentialsTested: BRUTE_FORCE_CREDENTIALS.length,
    });
  }

  // ── Severity ───────────────────────────────────────────────────────
  results.vulnerable = results.findings.length > 0;
  const hasDefaultCreds = results.findings.some((f) => f.credentials);
  if (hasDefaultCreds) {
    results.severity = 'HIGH';
  } else if (results.findings.length >= 2) {
    results.severity = 'MEDIUM';
  } else if (results.findings.length >= 1) {
    results.severity = 'LOW';
  }

  results.endTime = Date.now();
  results.durationMs = results.endTime - results.startTime;
  logger.info(`[RateLimit] Completed — ${results.findings.length} finding(s), severity: ${results.severity}`);

  return results;
}
