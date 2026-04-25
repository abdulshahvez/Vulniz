import logger from '../utils/logger.js';

/**
 * Validate the target URL supplied by the user.
 * Rules:
 *  1. Must be a valid URL (http or https)
 *  2. Must not target localhost / 127.0.0.1 / internal IPs (unless dev mode)
 *  3. Must not target well-known third-party services to prevent misuse
 */
const BLOCKED_HOSTS = [
  'google.com', 'facebook.com', 'twitter.com', 'github.com',
  'amazon.com', 'microsoft.com', 'apple.com', 'cloudflare.com',
];

const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
];

export function validateTargetUrl(req, res, next) {
  const { targetUrl } = req.body;

  if (!targetUrl) {
    return res.status(400).json({ error: 'targetUrl is required.' });
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  // Protocol check
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).json({ error: 'Only HTTP and HTTPS protocols are allowed.' });
  }

  const hostname = parsed.hostname.toLowerCase();

  // Allow localhost in development for testing with the vulnerable API
  const isDev = process.env.NODE_ENV !== 'production';
  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';

  if (isLocalhost && !isDev) {
    return res.status(400).json({ error: 'Scanning localhost is not allowed in production.' });
  }

  // Block private IPs in production
  if (!isDev && PRIVATE_IP_RANGES.some((re) => re.test(hostname))) {
    return res.status(400).json({ error: 'Scanning private/internal IPs is not allowed.' });
  }

  // Block well-known third-party domains
  if (BLOCKED_HOSTS.some((h) => hostname === h || hostname.endsWith(`.${h}`))) {
    return res.status(403).json({
      error: 'Scanning third-party services you do not own is prohibited.',
    });
  }

  // Attach parsed URL to request for downstream use
  req.parsedTarget = parsed;
  logger.info(`Validated target URL: ${targetUrl}`);
  next();
}

/**
 * Validate scan options (attack types to run, etc.)
 */
export function validateScanOptions(req, res, next) {
  const validAttacks = ['sql-injection', 'xss', 'rate-limit', 'header-security', 'auth-bypass'];
  const { attacks } = req.body;

  if (attacks && !Array.isArray(attacks)) {
    return res.status(400).json({ error: '`attacks` must be an array of attack type strings.' });
  }

  if (attacks) {
    const invalid = attacks.filter((a) => !validAttacks.includes(a));
    if (invalid.length) {
      return res.status(400).json({
        error: `Unknown attack types: ${invalid.join(', ')}`,
        validTypes: validAttacks,
      });
    }
  }

  // Default: run all attacks
  req.body.attacks = attacks || validAttacks;
  next();
}
