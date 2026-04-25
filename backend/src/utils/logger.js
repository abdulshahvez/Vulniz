import winston from 'winston';
import config from '../config/index.js';

/**
 * Application-wide logger powered by Winston.
 * - Console transport with colorized output in development
 * - JSON format in production for structured log ingestion
 */
const logger = winston.createLogger({
  level: config.isDev ? 'debug' : 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    config.isDev
      ? winston.format.combine(
          winston.format.colorize(),
          winston.format.printf(({ timestamp, level, message, stack }) => {
            return `${timestamp} [${level}]: ${stack || message}`;
          }),
        )
      : winston.format.json(),
  ),
  transports: [new winston.transports.Console()],
});

export default logger;
