import jobQueue from '../queue/job-queue.js';
import { discoverEndpoints } from '../services/scanner.service.js';
import logger from '../utils/logger.js';

/**
 * Scan Controller
 * ───────────────
 * Handles all scan-related HTTP endpoints.
 */

/**
 * POST /api/scan — Start a new security scan
 */
export function startScan(req, res) {
  const { targetUrl, attacks } = req.body;

  try {
    const job = jobQueue.createJob({ targetUrl, attacks });
    logger.info(`Scan job created: ${job.id} → ${targetUrl}`);

    res.status(201).json({
      message: 'Scan started',
      job,
    });
  } catch (err) {
    logger.error('Failed to create scan job:', err);
    res.status(500).json({ error: 'Failed to start scan.' });
  }
}

/**
 * GET /api/scan/:id — Get scan status / results
 */
export function getScanStatus(req, res) {
  const job = jobQueue.getJob(req.params.id);
  if (!job) {
    return res.status(404).json({ error: 'Scan not found.' });
  }
  res.json(job);
}

/**
 * GET /api/scan — List all scans
 */
export function listScans(_req, res) {
  const jobs = jobQueue.getAllJobs();
  res.json({ scans: jobs, total: jobs.length });
}

/**
 * GET /api/scan/:id/stream — SSE stream for real-time progress
 */
export function streamScanProgress(req, res) {
  const jobId = req.params.id;
  const job = jobQueue.getJob(jobId);

  if (!job) {
    return res.status(404).json({ error: 'Scan not found.' });
  }

  // Set up SSE
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  // Send current state immediately
  sendSSE(res, 'status', {
    id: job.id,
    status: job.status,
    progress: job.progress,
    currentAttack: job.currentAttack,
    logs: job.logs,
  });

  // If already complete, close
  if (job.status === 'completed' || job.status === 'failed') {
    sendSSE(res, 'complete', {
      id: job.id,
      status: job.status,
      score: job.score,
      analysis: job.analysis,
    });
    res.end();
    return;
  }

  // Listen for updates
  const onProgress = (updatedJob) => {
    if (updatedJob.id !== jobId) return;
    sendSSE(res, 'progress', {
      progress: updatedJob.progress,
      currentAttack: updatedJob.currentAttack,
      status: updatedJob.status,
    });
  };

  const onLog = (logEntry) => {
    if (logEntry.jobId !== jobId) return;
    sendSSE(res, 'log', logEntry);
  };

  const onComplete = (completedJob) => {
    if (completedJob.id !== jobId) return;
    sendSSE(res, 'complete', {
      id: completedJob.id,
      status: completedJob.status,
      score: completedJob.score,
      analysis: completedJob.analysis,
      fixes: completedJob.fixes,
      results: completedJob.results,
    });
    cleanup();
    res.end();
  };

  const onFailed = (failedJob) => {
    if (failedJob.id !== jobId) return;
    sendSSE(res, 'error', {
      id: failedJob.id,
      error: failedJob.error,
    });
    cleanup();
    res.end();
  };

  function cleanup() {
    jobQueue.off('job:progress', onProgress);
    jobQueue.off('job:log', onLog);
    jobQueue.off('job:completed', onComplete);
    jobQueue.off('job:failed', onFailed);
  }

  jobQueue.on('job:progress', onProgress);
  jobQueue.on('job:log', onLog);
  jobQueue.on('job:completed', onComplete);
  jobQueue.on('job:failed', onFailed);

  // Clean up on client disconnect
  req.on('close', cleanup);
}

/**
 * POST /api/scan/discover — Discover endpoints from a base URL
 */
export async function discoverApi(req, res) {
  const { baseUrl } = req.body;

  if (!baseUrl) {
    return res.status(400).json({ error: 'baseUrl is required.' });
  }

  try {
    new URL(baseUrl);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  try {
    const result = await discoverEndpoints(baseUrl);
    res.json(result);
  } catch (err) {
    logger.error('Endpoint discovery failed:', err);
    res.status(500).json({ error: 'Endpoint discovery failed.' });
  }
}

// ── Helper ───────────────────────────────────────────────────────────
function sendSSE(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}
