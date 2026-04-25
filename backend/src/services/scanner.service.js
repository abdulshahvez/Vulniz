import httpClient from '../utils/http-client.js';
import logger from '../utils/logger.js';

/**
 * Auto API Scanner Service
 * ────────────────────────
 * Accepts a base URL, discovers endpoints via basic crawling,
 * and returns a list of discovered endpoints for batch scanning.
 */

/** Common API path patterns to probe */
const COMMON_PATHS = [
  '/',
  '/api',
  '/api/v1',
  '/api/v2',
  '/api/users',
  '/api/user',
  '/api/auth',
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/signup',
  '/api/login',
  '/api/register',
  '/api/admin',
  '/api/products',
  '/api/items',
  '/api/orders',
  '/api/search',
  '/api/data',
  '/api/profile',
  '/api/settings',
  '/api/config',
  '/api/health',
  '/api/status',
  '/api/info',
  '/api/docs',
  '/api/swagger',
  '/api/graphql',
  '/users',
  '/login',
  '/register',
  '/admin',
  '/dashboard',
  '/search',
  '/health',
  '/status',
  '/swagger.json',
  '/openapi.json',
  '/robots.txt',
  '/sitemap.xml',
  '/.env',
  '/.git',
  '/.git/config',
  '/wp-admin',
  '/wp-login.php',
];

const METHODS_TO_PROBE = ['GET', 'POST', 'PUT', 'DELETE'];

/**
 * Discover API endpoints from a base URL.
 *
 * @param {string} baseUrl - The base URL to scan
 * @param {object} [options] - Scan options
 * @param {function} [onProgress] - Progress callback
 * @returns {Promise<object>} - Discovered endpoints
 */
export async function discoverEndpoints(baseUrl, options = {}, onProgress = null) {
  logger.info(`[Scanner] Starting endpoint discovery on ${baseUrl}`);

  // Normalise base URL
  const base = baseUrl.replace(/\/+$/, '');
  const discovered = [];
  const totalPaths = COMMON_PATHS.length;
  let completed = 0;

  for (const path of COMMON_PATHS) {
    const url = `${base}${path}`;

    try {
      // Quick HEAD/GET to see if the endpoint exists
      const res = await httpClient.get(url, { timeout: 5000 });

      if (res.status > 0 && res.status < 500 && res.status !== 404) {
        const endpoint = {
          url,
          path,
          method: 'GET',
          statusCode: res.status,
          contentType: res.headers?.['content-type'] || 'unknown',
          responseSize: JSON.stringify(res.data || '').length,
          responseTime: res.duration || 0,
        };

        // Check if this path also responds to other methods
        const supportedMethods = ['GET'];
        for (const method of ['POST', 'PUT', 'DELETE']) {
          try {
            const methodRes = await httpClient.request({
              method: method.toLowerCase(),
              url,
              timeout: 3000,
            });
            if (methodRes.status < 500 && methodRes.status !== 404 && methodRes.status !== 405) {
              supportedMethods.push(method);
            }
          } catch {
            // Method not supported — fine
          }
        }

        endpoint.supportedMethods = supportedMethods;
        discovered.push(endpoint);
        logger.debug(`[Scanner] Found: ${path} (${res.status}) [${supportedMethods.join(', ')}]`);
      }
    } catch (err) {
      // Path doesn't exist or timed out — skip
    }

    completed++;
    if (onProgress) {
      onProgress({
        phase: 'discovery',
        completed,
        total: totalPaths,
        percent: Math.round((completed / totalPaths) * 100),
        lastPath: path,
      });
    }
  }

  // ── Try to parse Swagger/OpenAPI docs ──────────────────────────────
  const swaggerPaths = ['/swagger.json', '/openapi.json', '/api-docs', '/docs/api'];
  for (const sp of swaggerPaths) {
    try {
      const res = await httpClient.get(`${base}${sp}`, { timeout: 5000 });
      if (res.status === 200 && res.data) {
        const data = typeof res.data === 'string' ? JSON.parse(res.data) : res.data;
        if (data.paths) {
          for (const [path, methods] of Object.entries(data.paths)) {
            for (const method of Object.keys(methods)) {
              if (['get', 'post', 'put', 'delete', 'patch'].includes(method)) {
                const fullUrl = `${base}${path}`;
                if (!discovered.find((d) => d.url === fullUrl && d.method === method.toUpperCase())) {
                  discovered.push({
                    url: fullUrl,
                    path,
                    method: method.toUpperCase(),
                    statusCode: null,
                    source: 'openapi',
                    supportedMethods: [method.toUpperCase()],
                  });
                }
              }
            }
          }
          logger.info(`[Scanner] Parsed OpenAPI spec from ${sp}`);
        }
      }
    } catch {
      // No swagger doc — fine
    }
  }

  const result = {
    baseUrl: base,
    totalProbed: totalPaths,
    discovered: discovered.length,
    endpoints: discovered,
    scannedAt: new Date().toISOString(),
  };

  logger.info(`[Scanner] Discovery complete — found ${discovered.length} endpoints`);
  return result;
}
