import express from 'express';

/**
 * ╔═══════════════════════════════════════════════════════════════════╗
 * ║  INTENTIONALLY VULNERABLE API — FOR TESTING ONLY                ║
 * ║  DO NOT deploy this in production or expose to the internet.    ║
 * ╚═══════════════════════════════════════════════════════════════════╝
 *
 * This server deliberately contains common security vulnerabilities
 * so you can test Vulniz against a known target.
 */

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── No security headers whatsoever (intentional) ─────────────────────
// No helmet, no CORS restrictions, no CSP

// Wildcard CORS (vulnerable)
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  // Intentionally leaking server info
  res.setHeader('X-Powered-By', 'Express 4.18.2');
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
  next();
});

// ── Fake in-memory database ──────────────────────────────────────────
const users = [
  { id: 1, username: 'admin', password: 'admin123', email: 'admin@example.com', role: 'admin', salary: 150000 },
  { id: 2, username: 'user', password: 'password', email: 'user@example.com', role: 'user', salary: 50000 },
  { id: 3, username: 'john', password: 'john2024', email: 'john@example.com', role: 'user', salary: 65000 },
  { id: 4, username: 'test', password: 'test', email: 'test@test.com', role: 'user', salary: 45000 },
];

const products = [
  { id: 1, name: 'Widget A', price: 29.99, secret_cost: 5.00 },
  { id: 2, name: 'Widget B', price: 49.99, secret_cost: 8.50 },
  { id: 3, name: 'Premium Widget', price: 199.99, secret_cost: 25.00 },
];

// ── VULNERABILITY: SQL Injection (simulated) ─────────────────────────
// This simulates what happens when user input is used in SQL queries
// without parameterization.
app.get('/api/users', (req, res) => {
  const { search } = req.query;

  if (search) {
    // Simulate SQL injection vulnerability — if input contains SQL syntax,
    // "leak" all data as if the injection succeeded
    const lowerSearch = (search || '').toLowerCase();
    if (
      lowerSearch.includes("'") ||
      lowerSearch.includes('or 1=1') ||
      lowerSearch.includes('union') ||
      lowerSearch.includes('select') ||
      lowerSearch.includes('drop') ||
      lowerSearch.includes('--')
    ) {
      // Simulated SQL error message leak
      if (lowerSearch.includes('error') || lowerSearch.includes('convert')) {
        return res.status(500).json({
          error: "You have an error in your SQL syntax near '" + search + "' at line 1",
          query: `SELECT * FROM users WHERE username = '${search}'`,
        });
      }
      // Simulated data leak via SQL injection
      return res.json({
        message: 'Search results',
        query: `SELECT * FROM users WHERE username = '${search}'`,
        results: users, // Leaking ALL user data including passwords
      });
    }

    const filtered = users.filter((u) =>
      u.username.toLowerCase().includes(lowerSearch),
    );
    return res.json({ results: filtered.map(({ password, salary, ...u }) => u) });
  }

  // No search — return sanitized data
  res.json({ results: users.map(({ password, salary, ...u }) => u) });
});

// ── VULNERABILITY: XSS (Reflected) ──────────────────────────────────
// Reflects user input without sanitization
app.get('/api/search', (req, res) => {
  const { q } = req.query;
  // Reflecting input directly — XSS vulnerability
  res.send(`<html><body><h1>Search Results for: ${q}</h1><p>No results found for "${q}"</p></body></html>`);
});

app.post('/api/search', (req, res) => {
  const { input, comment, name, search, message } = req.body;
  const userInput = input || comment || name || search || message || '';
  // Reflecting POST input without sanitization
  res.json({
    message: `You searched for: ${userInput}`,
    input: userInput,
    results: [],
  });
});

// ── VULNERABILITY: No Authentication ─────────────────────────────────
// Sensitive endpoints with no auth checks
app.get('/api/admin', (_req, res) => {
  res.json({
    panel: 'Admin Dashboard',
    users: users, // Full user list with passwords
    secrets: {
      apiKey: 'sk-secret-12345-abcdef',
      dbPassword: 'super_secret_db_pass',
      jwtSecret: 'my-jwt-secret-key',
    },
  });
});

// ── VULNERABILITY: No rate limiting on login ─────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  // No rate limiting, no account lockout
  const user = users.find(
    (u) => u.username === username && u.password === password,
  );

  if (user) {
    // Returning too much data + weak token
    return res.json({
      success: true,
      message: 'Login successful',
      token: Buffer.from(`${user.id}:${user.role}:${Date.now()}`).toString('base64'),
      user: user, // Leaking password in response!
    });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// ── VULNERABILITY: Broken token validation ───────────────────────────
app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization || req.headers['x-auth-token'] || '';

  // Accepts ANY token without verification
  if (authHeader) {
    return res.json({
      user: users[0], // Always returns admin data
      token: authHeader,
      sessionValid: true,
    });
  }

  // Even without token, returns data
  res.json({ user: { username: 'guest', role: 'user' } });
});

// ── VULNERABILITY: IDOR — No ownership check ─────────────────────────
app.get('/api/users/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const user = users.find((u) => u.id === id);

  if (user) {
    return res.json(user); // Returns full data including password
  }

  res.status(404).json({ error: 'User not found' });
});

// ── VULNERABILITY: Mass assignment ───────────────────────────────────
app.put('/api/users/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const user = users.find((u) => u.id === id);

  if (user) {
    Object.assign(user, req.body); // Accepts ANY field including role
    return res.json({ message: 'User updated', user });
  }

  res.status(404).json({ error: 'User not found' });
});

app.delete('/api/users/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const idx = users.findIndex((u) => u.id === id);
  if (idx !== -1) {
    users.splice(idx, 1);
    return res.json({ message: 'User deleted' });
  }
  res.status(404).json({ error: 'User not found' });
});

// ── Products endpoint ────────────────────────────────────────────────
app.get('/api/products', (_req, res) => {
  res.json({ products }); // Leaks secret_cost
});

// ── Health ───────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', vulnerable: true });
});

app.get('/', (_req, res) => {
  res.json({
    service: 'Vulnerable Test API',
    warning: 'THIS API IS INTENTIONALLY VULNERABLE — FOR TESTING ONLY',
    endpoints: [
      'GET  /api/users?search=...',
      'GET  /api/users/:id',
      'PUT  /api/users/:id',
      'DELETE /api/users/:id',
      'POST /api/auth/login',
      'GET  /api/profile',
      'GET  /api/admin',
      'GET  /api/search?q=...',
      'POST /api/search',
      'GET  /api/products',
      'GET  /api/health',
    ],
  });
});

// ── Start ────────────────────────────────────────────────────────────
const PORT = process.env.VULNERABLE_API_PORT || 3002;
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║  ⚠  VULNERABLE TEST API — DO NOT EXPOSE TO INTERNET  ⚠  ║
║──────────────────────────────────────────────────────────║
║  Running on: http://localhost:${PORT}                       ║
║  Purpose:    Testing Vulniz                                ║
╚══════════════════════════════════════════════════════════╝
  `);
});
