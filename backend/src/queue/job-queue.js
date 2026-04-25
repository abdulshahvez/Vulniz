import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';
import config from '../config/index.js';
import logger from '../utils/logger.js';
import attackModules from '../services/attacks/index.js';
import httpClient from '../utils/http-client.js';
import { analyzeResults } from '../services/analysis.service.js';
import { calculateScore } from '../services/scoring.service.js';
import { generateFixSuggestions } from '../services/ai.service.js';

/**
 * In-Memory Job Queue
 * ───────────────────
 * Manages scan jobs with concurrency control, progress tracking,
 * and event-based notifications (used for SSE).
 *
 * Can be swapped for BullMQ + Redis by implementing the same interface.
 */

class JobQueue extends EventEmitter {
  constructor() {
    super();
    /** @type {Map<string, object>} */
    this.jobs = new Map();
    this.activeCount = 0;
    this.maxConcurrent = config.scan.maxConcurrent;
    this.queue = []; // pending job IDs
  }

  /**
   * Create a new scan job.
   * @param {object} params
   * @param {string} params.targetUrl
   * @param {string[]} params.attacks
   * @returns {object} job metadata
   */
  createJob({ targetUrl, attacks }) {
    const id = uuidv4();
    const job = {
      id,
      targetUrl,
      attacks,
      status: 'queued', // queued | running | completed | failed
      progress: 0,
      currentAttack: null,
      results: [],
      analysis: null,
      score: null,
      fixes: null,
      logs: [],
      createdAt: new Date().toISOString(),
      startedAt: null,
      completedAt: null,
      error: null,
    };

    this.jobs.set(id, job);
    this.queue.push(id);
    this._addLog(job, `Job created — target: ${targetUrl}`);
    this._addLog(job, `Attacks queued: ${attacks.join(', ')}`);
    this.emit('job:created', job);

    // Try to process immediately
    this._processNext();

    return { id: job.id, status: job.status, createdAt: job.createdAt };
  }

  /**
   * Get job status.
   */
  getJob(id) {
    return this.jobs.get(id) || null;
  }

  /**
   * Get all jobs (most recent first).
   */
  getAllJobs() {
    return [...this.jobs.values()]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map((j) => ({
        id: j.id,
        targetUrl: j.targetUrl,
        status: j.status,
        progress: j.progress,
        score: j.score?.score ?? null,
        riskLevel: j.score?.riskLevel ?? null,
        createdAt: j.createdAt,
        completedAt: j.completedAt,
      }));
  }

  /**
   * Process the next queued job if concurrency allows.
   */
  _processNext() {
    if (this.activeCount >= this.maxConcurrent || this.queue.length === 0) return;

    const jobId = this.queue.shift();
    const job = this.jobs.get(jobId);
    if (!job) return;

    this.activeCount++;
    this._runJob(job).finally(() => {
      this.activeCount--;
      this._processNext();
    });
  }

  /**
   * Execute all attack modules for a job.
   */
  async _runJob(job) {
    job.status = 'running';
    job.startedAt = new Date().toISOString();
    this._addLog(job, '▶ Scan started');
    this.emit('job:started', job);

    const totalSteps = job.attacks.length + 2; // +2 for analysis + scoring
    let completedSteps = 0;

    try {
      // ── Pre-scan reachability check ───────────────────────────────
      this._addLog(job, '📡 Verifying target URL is reachable…');
      const ping = await httpClient.get(job.targetUrl);
      if (ping.error) {
        throw new Error(`Target unreachable: ${ping.errorMessage || ping.statusText}`);
      }
      if (ping.status === 404) {
        throw new Error('Target invalid: The endpoint returned 404 Not Found. Please check the URL.');
      }
      this._addLog(job, `✓ Target is reachable (HTTP ${ping.status})`);

      // ── Run each attack module ───────────────────────────────────
      for (const attackType of job.attacks) {
        const runner = attackModules[attackType];
        if (!runner) {
          this._addLog(job, `⚠ Unknown attack type: ${attackType} — skipping`);
          continue;
        }

        job.currentAttack = attackType;
        this._addLog(job, `🔍 Running ${attackType}…`);
        this.emit('job:progress', job);

        try {
          const result = await runner(job.targetUrl);
          job.results.push(result);
          this._addLog(
            job,
            `${result.vulnerable ? '⚠' : '✓'} ${attackType}: ${result.findings.length} finding(s) — ${result.severity}`,
          );
        } catch (err) {
          this._addLog(job, `✗ ${attackType} failed: ${err.message}`);
          job.results.push({
            attackType,
            vulnerable: false,
            severity: 'NONE',
            findings: [],
            error: err.message,
          });
        }

        completedSteps++;
        job.progress = Math.round((completedSteps / totalSteps) * 100);
        this.emit('job:progress', job);
      }

      // ── Analysis ─────────────────────────────────────────────────
      job.currentAttack = null;
      this._addLog(job, '📊 Analyzing results…');
      job.analysis = analyzeResults(job.results);
      completedSteps++;
      job.progress = Math.round((completedSteps / totalSteps) * 100);
      this.emit('job:progress', job);

      // ── Scoring ──────────────────────────────────────────────────
      this._addLog(job, '📈 Calculating security score…');
      job.score = calculateScore(job.analysis);
      completedSteps++;
      job.progress = Math.round((completedSteps / totalSteps) * 100);
      this.emit('job:progress', job);

      // ── Fix suggestions ──────────────────────────────────────────
      this._addLog(job, '🤖 Generating fix suggestions…');
      job.fixes = await generateFixSuggestions(job.analysis, job.score);

      // ── Done ─────────────────────────────────────────────────────
      job.status = 'completed';
      job.progress = 100;
      job.completedAt = new Date().toISOString();
      this._addLog(job, `✅ Scan complete — Score: ${job.score.score}/100 (${job.score.riskLevel})`);
      this.emit('job:completed', job);
    } catch (err) {
      job.status = 'failed';
      job.error = err.message;
      job.completedAt = new Date().toISOString();
      this._addLog(job, `❌ Scan failed: ${err.message}`);
      this.emit('job:failed', job);
      logger.error(`Job ${job.id} failed:`, err);
    }
  }

  /**
   * Append a timestamped log entry to the job.
   */
  _addLog(job, message) {
    const entry = {
      timestamp: new Date().toISOString(),
      message,
    };
    job.logs.push(entry);
    this.emit('job:log', { jobId: job.id, ...entry });
    logger.debug(`[Job ${job.id.substring(0, 8)}] ${message}`);
  }
}

// Export a singleton
const jobQueue = new JobQueue();
export default jobQueue;
