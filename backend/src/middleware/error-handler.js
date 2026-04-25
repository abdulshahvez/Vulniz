import logger from '../utils/logger.js';

/**
 * Global Express error-handling middleware.
 * Catches unhandled errors, logs them, and returns a safe JSON response.
 */
export function errorHandler(err, _req, res, _next) {
  logger.error(err);

  const status = err.statusCode || err.status || 500;
  const message =
    process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message || 'Internal server error';

  res.status(status).json({
    error: message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
}

/**
 * Catch-all for undefined routes.
 */
export function notFoundHandler(_req, res) {
  res.status(404).json({ error: 'Endpoint not found.' });
}
