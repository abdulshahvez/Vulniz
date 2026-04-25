# Vulniz

A robust, full-stack platform designed to test REST APIs against common vulnerabilities (OWASP top risks) and provide actionable remediation insights. 

Built with Node.js, Express, React, and an optional AI layer (OpenAI) for intelligent fix suggestions.

## Features

- **Automated Scanning**: Tests for SQL Injection, Reflected XSS, Auth Bypass, Rate Limiting, and Security Headers.
- **Dynamic Analysis**: Detects anomalies in API responses, including time-delays, data leakage, and unexpected success codes.
- **Scoring Engine**: Calculates a security score (0-100) and risk level.
- **AI-Powered Remediation**: Uses OpenAI to generate custom, context-aware code fixes and best practices (falls back to an extensive built-in engine if no API key is provided).
- **PDF Reports**: Export scan results and recommendations as professional PDF documents.
- **Vulnerable API Included**: Comes with an intentionally vulnerable target (`http://localhost:3002`) for safe testing and demonstration.
- **Premium UI**: Dark-themed, glassmorphic dashboard with real-time SSE progress streaming.

## Project Structure

```
api-attack-simulator/
├── backend/
│   ├── src/                 # Core engine, API routes, queue
│   ├── vulnerable-api/      # Intentionally vulnerable server
│   └── package.json
└── frontend/
    ├── src/                 # React dashboard
    └── package.json
```

## Quick Start (Development)

### Prerequisites
- Node.js v18+ 
- (Optional) OpenAI API Key for AI suggestions

### Setup Backend

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up environment variables. The `.env` file is already created. Optionally, edit `.env` to add your `OPENAI_API_KEY`.
4. Start the backend and the vulnerable test API:
   ```bash
   npm run dev:all
   ```
   *The main API will run on `http://localhost:3001` and the Vulnerable API on `http://localhost:3002`.*

### Setup Frontend

1. Open a new terminal and navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Vite dev server:
   ```bash
   npm run dev
   ```
4. Open your browser to `http://localhost:5173`.

## How to Test

1. Ensure both the backend (`npm run dev:all`) and frontend (`npm run dev`) are running.
2. Open the dashboard at `http://localhost:5173`.
3. In the "Target Configuration" panel, enter the vulnerable test API URL:
   `http://localhost:3002/api/users` 
   *(You can also test `/api/search` or `/api/auth/login`)*
4. Select the attacks you want to simulate and click **Launch Scan**.
5. Watch the real-time progress.
6. Review the vulnerabilities, breakdown, and suggested fixes in the results dashboard.
7. Click "Download PDF" to generate a report.

## Important Note

**This tool is for educational and defensive purposes only.** Do not run this scanner against APIs or servers that you do not own or have explicit permission to test.
