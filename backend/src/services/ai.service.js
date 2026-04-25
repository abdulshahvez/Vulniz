import config from '../config/index.js';
import logger from '../utils/logger.js';

/**
 * AI-Powered Fix Suggestion Service
 * ──────────────────────────────────
 * Uses the OpenAI API to generate context-aware security fixes,
 * code snippets, and OWASP-aligned best practices.
 *
 * Falls back to a built-in suggestion engine when no API key is set.
 */

// ── Built-in fix templates (used when OpenAI is unavailable) ─────────
const BUILTIN_FIXES = {
  'sql-injection': {
    title: 'Prevent SQL Injection',
    description: 'Use parameterized queries instead of string concatenation.',
    codeSnippet: `// ❌ Vulnerable
const query = "SELECT * FROM users WHERE username = '" + username + "'";

// ✅ Safe — parameterized query (Node.js + mysql2)
const [rows] = await db.execute(
  'SELECT * FROM users WHERE username = ?',
  [username]
);

// ✅ Safe — using an ORM (Sequelize)
const user = await User.findOne({ where: { username } });`,
    bestPractices: [
      'Always use parameterized queries or prepared statements',
      'Use an ORM like Sequelize, Prisma, or Knex.js',
      'Validate and sanitize all user input on the server side',
      'Apply the principle of least privilege to database accounts',
      'Implement input length limits',
    ],
    owaspRef: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
  },
  'xss': {
    title: 'Prevent Cross-Site Scripting (XSS)',
    description: 'Encode output and set proper Content-Security-Policy headers.',
    codeSnippet: `// ❌ Vulnerable — reflecting raw input
app.get('/search', (req, res) => {
  res.send(\`Results for: \${req.query.q}\`);
});

// ✅ Safe — encode output
import escapeHtml from 'escape-html';
app.get('/search', (req, res) => {
  res.send(\`Results for: \${escapeHtml(req.query.q)}\`);
});

// ✅ Safe — return JSON with proper Content-Type
app.get('/api/search', (req, res) => {
  res.json({ query: req.query.q, results: [] });
});

// ✅ Add CSP header
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});`,
    bestPractices: [
      'Always encode/escape user input before rendering',
      'Use Content-Security-Policy headers',
      'Set X-Content-Type-Options: nosniff',
      'Use frameworks that auto-escape by default (React, Angular)',
      'Validate input against allowlists',
    ],
    owaspRef: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
  },
  'rate-limit': {
    title: 'Implement Rate Limiting',
    description: 'Add rate limiting middleware to protect against brute force and DoS.',
    codeSnippet: `// ✅ Using express-rate-limit
import rateLimit from 'express-rate-limit';

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/', apiLimiter);

// Strict limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // only 5 login attempts per window
  skipSuccessfulRequests: true,
});
app.use('/api/auth/login', authLimiter);

// ✅ Also implement account lockout
let failedAttempts = {};
app.post('/api/auth/login', (req, res) => {
  const key = req.body.username;
  if (failedAttempts[key] >= 5) {
    return res.status(423).json({ error: 'Account locked. Try again in 30 minutes.' });
  }
  // ... authentication logic
});`,
    bestPractices: [
      'Apply rate limiting to all public-facing endpoints',
      'Use stricter limits on authentication endpoints',
      'Implement account lockout after repeated failures',
      'Use CAPTCHA for login forms after failed attempts',
      'Consider IP-based and user-based rate limiting',
      'Log and alert on rate limit violations',
    ],
    owaspRef: 'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
  },
  'header-security': {
    title: 'Configure Security Headers',
    description: 'Add required security headers using Helmet.js or manually.',
    codeSnippet: `// ✅ Using Helmet.js (recommended)
import helmet from 'helmet';
app.use(helmet());

// ✅ Or set headers manually
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Enable HSTS
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  // CSP
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Permissions policy
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // Remove server info
  res.removeHeader('X-Powered-By');
  next();
});

// ✅ Restrict CORS
import cors from 'cors';
app.use(cors({
  origin: ['https://yourdomain.com'],
  credentials: true,
}));`,
    bestPractices: [
      'Use Helmet.js for Express applications',
      'Configure strict CORS policies — never use wildcard with credentials',
      'Enable HSTS on all production endpoints',
      'Remove X-Powered-By and Server headers',
      'Implement Content-Security-Policy',
    ],
    owaspRef: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
  },
  'auth-bypass': {
    title: 'Strengthen Authentication & Authorization',
    description: 'Validate tokens properly and enforce authorization checks.',
    codeSnippet: `// ✅ Proper JWT verification
import jwt from 'jsonwebtoken';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    // ALWAYS specify the algorithm to prevent alg=none attacks
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
    });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ✅ Role-based authorization
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// ✅ Protect routes
app.get('/api/admin', authMiddleware, requireRole('admin'), handler);
app.get('/api/users/:id', authMiddleware, checkOwnership, handler);`,
    bestPractices: [
      'Always verify JWT signatures with a fixed algorithm',
      'Never trust client-side tokens without server-side validation',
      'Implement role-based access control (RBAC)',
      'Check resource ownership for IDOR prevention',
      'Use short-lived tokens with refresh rotation',
      'Invalidate tokens on password change and logout',
    ],
    owaspRef: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
  },
};

/**
 * Generate AI-powered fix suggestions for the given findings.
 *
 * @param {object} analysis - Output from the analysis engine
 * @param {object} scoreReport - Output from the scoring engine
 * @returns {Promise<object>} - Fix suggestions by attack type
 */
export async function generateFixSuggestions(analysis, scoreReport) {
  logger.info('[AI] Generating fix suggestions…');

  const vulnerableTypes = new Set();
  for (const f of [
    ...(analysis.criticalFindings || []),
    ...(analysis.highFindings || []),
    ...(analysis.mediumFindings || []),
    ...(analysis.lowFindings || []),
  ]) {
    vulnerableTypes.add(f.attackType);
  }

  // ── 1. Try Google Gemini (Preferred for Free Tier) ─────────────────
  if (config.geminiApiKey && !config.geminiApiKey.startsWith('YOUR')) {
    try {
      const { GoogleGenerativeAI } = await import('@google/generative-ai');
      const genAI = new GoogleGenerativeAI(config.geminiApiKey);
      const model = genAI.getGenerativeModel({ 
        model: 'gemini-1.5-flash',
        generationConfig: { responseMimeType: 'application/json' }
      });

      const prompt = buildPrompt(analysis, scoreReport);
      const result = await model.generateContent({
        contents: [{ role: 'user', parts: [{ text: `You are a senior application security engineer. Provide actionable, production-ready fixes for API vulnerabilities. Focus on Node.js/Express. Return JSON with keys matching each attack type. \n\n ${prompt}` }] }],
      });

      const response = await result.response;
      const aiResponse = JSON.parse(response.text());
      logger.info('[AI] Gemini suggestions generated successfully');

      return mergeSuggestions(vulnerableTypes, aiResponse);
    } catch (err) {
      logger.warn(`[AI] Gemini failed: ${err.message}`);
      // Fall through to OpenAI if Gemini fails
    }
  }

  // ── 2. Try OpenAI (Secondary) ──────────────────────────────────────
  if (config.openaiApiKey && !config.openaiApiKey.startsWith('sk-your')) {
    try {
      const { default: OpenAI } = await import('openai');
      const openai = new OpenAI({ apiKey: config.openaiApiKey });

      const prompt = buildPrompt(analysis, scoreReport);
      const completion = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content:
              'You are a senior application security engineer. Provide actionable, production-ready fixes for API vulnerabilities. Focus on Node.js/Express. Return JSON with keys matching each attack type.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: 0.3,
        max_tokens: 4000,
        response_format: { type: 'json_object' },
      });

      const aiResponse = JSON.parse(completion.choices[0].message.content);
      logger.info('[AI] OpenAI suggestions generated successfully');

      return mergeSuggestions(vulnerableTypes, aiResponse);
    } catch (err) {
      logger.warn(`[AI] OpenAI failed: ${err.message}`);
      // Fall through to built-in
    }
  }

  // ── 3. Fallback to Built-in ────────────────────────────────────────
  logger.info('[AI] No AI keys configured or AI failed — using built-in suggestions');
  return getBuiltinSuggestions(vulnerableTypes, analysis);
}

/**
 * Merge AI response with built-in templates
 */
function mergeSuggestions(vulnerableTypes, aiResponse) {
  const merged = {};
  for (const type of vulnerableTypes) {
    merged[type] = {
      ...BUILTIN_FIXES[type],
      ...(aiResponse[type] || {}),
      source: 'ai',
    };
  }
  return merged;
}

/**
 * Return built-in fix suggestions for the given vulnerable attack types.
 */
function getBuiltinSuggestions(vulnerableTypes, analysis) {
  const suggestions = {};
  for (const type of vulnerableTypes) {
    if (BUILTIN_FIXES[type]) {
      suggestions[type] = { ...BUILTIN_FIXES[type], source: 'builtin' };
    }
  }
  return suggestions;
}

/**
 * Build a detailed prompt for the LLM.
 */
function buildPrompt(analysis, scoreReport) {
  return `
Analyze the following API security scan results and provide detailed fix suggestions.

## Security Score: ${scoreReport.score}/100 (${scoreReport.riskLevel})

## Findings Summary:
- Critical: ${scoreReport.breakdown.critical}
- High: ${scoreReport.breakdown.high}
- Medium: ${scoreReport.breakdown.medium}
- Low: ${scoreReport.breakdown.low}

## Detailed Findings:
${JSON.stringify(
  [
    ...(analysis.criticalFindings || []),
    ...(analysis.highFindings || []),
    ...(analysis.mediumFindings || []),
  ],
  null,
  2,
)}

For EACH vulnerability type found, provide:
1. "title" — short fix title
2. "description" — what the fix does
3. "codeSnippet" — production-ready Node.js/Express code
4. "bestPractices" — array of best practice strings
5. "owaspRef" — relevant OWASP cheat sheet URL

Return a JSON object keyed by attack type (sql-injection, xss, rate-limit, header-security, auth-bypass).
`.trim();
}
