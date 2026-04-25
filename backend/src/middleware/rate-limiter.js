import rateLimit from 'express-rate-limit';
import config from '../config/index.js';

/**
 * Platform-level rate limiter.
 * Prevents abuse of the scanning endpoints themselves.
 */
const platformLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests — please try again later.',
    retryAfterMs: config.rateLimit.windowMs,
  },
});

/**
 * Stricter limiter specifically for scan-initiation endpoints
 * (max 10 scans per 15-minute window).
 */
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Scan rate limit reached. Max 10 scans per 15 minutes.',
  },
});

export { platformLimiter, scanLimiter };
