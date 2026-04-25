import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import config from './config/index.js';
import logger from './utils/logger.js';
import { platformLimiter } from './middleware/rate-limiter.js';
import { errorHandler, notFoundHandler } from './middleware/error-handler.js';
import scanRoutes from './routes/scan.routes.js';
import reportRoutes from './routes/report.routes.js';

/**
 * Vulniz — Backend Server
 * ──────────────────────────────────────
 * Express application with security middleware, REST API routes,
 * and a queue-based scan engine.
 */

const app = express();

// ── Security middleware ──────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false })); // CSP off for dev convenience
app.use(cors({ origin: '*' })); // Adjust in production
app.use(platformLimiter);

// ── Body parsing ─────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Request logging ──────────────────────────────────────────────────
app.use((req, _res, next) => {
  logger.debug(`${req.method} ${req.url}`);
  next();
});

// ── Health check ─────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'api-attack-simulator',
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// ── API routes ───────────────────────────────────────────────────────
app.use('/api/scan', scanRoutes);
app.use('/api/report', reportRoutes);

// ── Error handling ───────────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

// ── Start server ─────────────────────────────────────────────────────
app.listen(config.port, () => {
  logger.info(`
╔══════════════════════════════════════════════╗
║             Vulniz — Backend                 ║
║──────────────────────────────────────────────║
║  Server:  http://localhost:${config.port}              ║
║  Env:     ${config.nodeEnv.padEnd(33)}║
║  Status:  Ready                              ║
╚══════════════════════════════════════════════╝
  `);
});

export default app;
