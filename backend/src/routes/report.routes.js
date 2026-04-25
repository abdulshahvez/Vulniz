import { Router } from 'express';
import { getReport, downloadPdfReport } from '../controllers/report.controller.js';

const router = Router();

/**
 * GET /api/report/:id
 * Get JSON report for a completed scan.
 */
router.get('/:id', getReport);

/**
 * GET /api/report/:id/pdf
 * Download PDF security report.
 */
router.get('/:id/pdf', downloadPdfReport);

export default router;
