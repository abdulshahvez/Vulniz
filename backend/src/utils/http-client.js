import axios from 'axios';
import config from '../config/index.js';
import logger from './logger.js';

/**
 * Pre-configured Axios instance used by every attack module.
 * - Enforces the global scan timeout
 * - Follows redirects (max 5)
 * - Returns full response even on 4xx/5xx so attack modules can inspect them
 */
const httpClient = axios.create({
  timeout: config.scan.timeoutMs,
  maxRedirects: 5,
  validateStatus: () => true, // never throw on HTTP status
  headers: {
    'User-Agent': 'APIAttackSimulator/1.0 (Security Scanner)',
  },
});

// ── Request interceptor ────────────────────────────────────────────
httpClient.interceptors.request.use((req) => {
  req._startTime = Date.now();
  logger.debug(`→ ${req.method?.toUpperCase()} ${req.url}`);
  return req;
});

// ── Response interceptor ───────────────────────────────────────────
httpClient.interceptors.response.use(
  (res) => {
    const duration = Date.now() - (res.config._startTime || Date.now());
    res.duration = duration;
    logger.debug(`← ${res.status} ${res.config.url} (${duration}ms)`);
    return res;
  },
  (err) => {
    const duration = Date.now() - (err.config?._startTime || Date.now());
    logger.debug(`✗ ${err.code || 'ERR'} ${err.config?.url} (${duration}ms)`);
    return Promise.resolve({
      status: 0,
      statusText: err.code || 'NETWORK_ERROR',
      data: null,
      headers: {},
      duration,
      error: true,
      errorMessage: err.message,
    });
  },
);

export default httpClient;
