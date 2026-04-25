import { Router } from 'express';
import { validateTargetUrl, validateScanOptions } from '../middleware/validator.js';
import { scanLimiter } from '../middleware/rate-limiter.js';
import {
  startScan,
  getScanStatus,
  listScans,
  streamScanProgress,
  discoverApi,
} from '../controllers/scan.controller.js';

const router = Router();

/**
 * POST /api/scan
 * Start a new security scan against a target URL.
 * Body: { targetUrl: string, attacks?: string[] }
 */
router.post('/', scanLimiter, validateTargetUrl, validateScanOptions, startScan);

/**
 * GET /api/scan
 * List all scan jobs (most recent first).
 */
router.get('/', listScans);

/**
 * GET /api/scan/:id
 * Get scan status and results.
 */
router.get('/:id', getScanStatus);

/**
 * GET /api/scan/:id/stream
 * SSE stream for real-time scan progress.
 */
router.get('/:id/stream', streamScanProgress);

/**
 * POST /api/scan/discover
 * Discover API endpoints from a base URL.
 * Body: { baseUrl: string }
 */
router.post('/discover', discoverApi);

export default router;
