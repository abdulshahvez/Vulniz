import dotenv from 'dotenv';
dotenv.config();

/**
 * Centralized configuration module.
 * All environment-driven settings are read here and exported
 * so that the rest of the codebase never reads process.env directly.
 */
const config = {
  port: parseInt(process.env.PORT, 10) || 3001,
  nodeEnv: process.env.NODE_ENV || 'development',
  isDev: (process.env.NODE_ENV || 'development') === 'development',

  // OpenAI
  openaiApiKey: process.env.OPENAI_API_KEY || '',

  // Redis (optional)
  redisUrl: process.env.REDIS_URL || '',

  // Rate limiting for the platform itself
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
  },

  // Scan engine
  scan: {
    maxConcurrent: parseInt(process.env.MAX_CONCURRENT_SCANS, 10) || 5,
    timeoutMs: parseInt(process.env.SCAN_TIMEOUT_MS, 10) || 30_000,
  },

  // Vulnerable test API
  vulnerableApiPort: parseInt(process.env.VULNERABLE_API_PORT, 10) || 3002,

  // Domain verification
  requireDomainVerification: process.env.REQUIRE_DOMAIN_VERIFICATION === 'true',
};

export default config;
