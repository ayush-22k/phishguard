# PhishGuard

PhishGuard is a cybersecurity web application for explainable, deterministic phishing-risk analysis of URLs and email content. It combines lexical, structural, and semantic heuristics with privacy-preserving persistence and robust authentication.

---

## 🏛️ Architecture Overview

PhishGuard follows a clean, modular multi-tier architecture:

```
[Browser / Client] (React 18, Vite, Tailwind CSS)
       │
       │ HTTP / Same-Origin via Vite Proxy (/api)
       ▼
[Vite Dev Server / Reverse Proxy] (Port 5173)
       │ (Forwards Cookie & Authorization headers)
       ▼
[Express.js REST API] (Port 5000)
       ├── Middleware: Helmet, CORS, Rate Limiters, JSON Size Limit, Structured Logger
       ├── Auth Layer: bcrypt (12 rounds), JWT access tokens (15m in-memory),
       │               HttpOnly SameSite=None refresh cookies (7d), session rotation
       ├── URL Analysis Engine: Lexical, structural, punycode, entropy, open redirect (0-100 score)
       ├── Email Analysis Engine: Semantic NLP heuristics, URL extraction & recursion, risk aggregation
       ├── AI Explanation Layer: Optional Google Gemini API (gemini-3.6-flash)
       │   └── Explains detector heuristics; cannot alter verdict, score, or indicators
       └── Repository Layer: Parameterized SQL with transactions & IDOR protection
       │
       ▼
[Neon Serverless PostgreSQL]
       ├── users (UUID, bcrypt hashes, roles: user/admin)
       ├── auth_sessions (revocable session rotation, token hash)
       ├── scans (metadata, scores, classifications, SHA-256 hashes)
       ├── scan_results (JSONB analysis, indicators, explanations)
       └── schema_migrations (versioned checksum tracking)
```

### Key Architectural Principles
- **Deterministic & Explainable:** Phish risk scores (0–100) are generated through rule-based weights and confidence scoring with structured indicators, never a black-box model.
- **Gemini is strictly an Explanation Layer:** Google Gemini (`gemini-3.6-flash`) only explains findings already identified by PhishGuard's deterministic detector. The AI engine *never* classifies threats independently, alters risk scores, or modifies verdicts.
- **SSRF Prevention:** The backend never fetches, browses, or downloads external URLs submitted for analysis. All analysis is performed statically and safely on raw strings.
- **Prompt Injection Defense:** User-controlled content and indicators are wrapped with untrusted data boundaries in AI prompts, preventing prompt-injection attacks from overriding detector facts.
- **Graceful Degradation:** Core scanning operates 100% independently of Gemini. If the AI API is rate-limited, times out, or fails, the core security report remains fully functional.
- **In-Memory JWT Tokens:** Access tokens live strictly in React state/memory, protecting them from XSS exfiltration. Refresh tokens reside exclusively in HttpOnly cookies.
- **Privacy-Preserving Persistence:** All URL and Email scan results are persisted in Neon PostgreSQL exclusively for authenticated users (enforcing strict IDOR protection). Raw email bodies are never stored in the database; only SHA-256 hashes and truncated subject previews are preserved. All database queries use strict parameterized SQL (`pg`) to prevent SQL injection.

---

## 📋 Prerequisites

Before running PhishGuard locally, ensure you have installed:
- **Node.js**: v18.0.0 or later (Node 20+ LTS recommended)
- **npm**: v9.0.0 or later
- **PostgreSQL**: Neon serverless account (or local PostgreSQL 15+)
- **OS**: Windows (PowerShell commands provided below), macOS, or Linux

---

## 🗄️ Neon PostgreSQL Setup

1. Sign up or log in to [Neon](https://neon.tech).
2. Create a new project (e.g., `phishguard`).
3. Under **Dashboard > Connection Details**, copy the pooled connection string (`postgresql://...`).
4. Ensure your connection string includes `sslmode=require`.

---

## 🔐 Environment Variables

### Backend Configuration (`backend/.env`)

Create `backend/.env` based on `backend/.env.example`:

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `PORT` | TCP port for the Express backend | `5000` |
| `CLIENT_URL` | Trusted frontend origin for CORS | `http://localhost:5173` |
| `NODE_ENV` | Environment mode (`development`, `production`, `test`) | `development` |
| `DATABASE_URL` | Neon PostgreSQL pooled connection string | `postgresql://...` |
| `JWT_SECRET` | Secret for signing access tokens (min 32 chars) | Random 32+ characters |
| `JWT_REFRESH_SECRET` | Secret for signing refresh tokens (min 32 chars) | Random 32+ characters |
| `JWT_ACCESS_EXPIRES_IN` | Access token lifespan | `15m` |
| `JWT_REFRESH_EXPIRES_DAYS` | Refresh token lifespan | `7` |
| `RATE_LIMIT_GLOBAL` | Max requests per 15 minutes globally | `300` |
| `RATE_LIMIT_AUTH` | Max requests per 15 minutes for auth endpoints | `100` |
| `RATE_LIMIT_SCAN` | Max requests per 15 minutes for scan endpoints | `50` |
| `RATE_LIMIT_AI` | Max requests per 15 minutes for AI endpoints | `5` |
| `GEMINI_API_KEY` | Google Generative AI API Key (`gemini-3.6-flash`) | `AIzaSy...` |

### Frontend Configuration (`frontend/.env`)

Create `frontend/.env` based on `frontend/.env.example`:

| Variable | Description | Value |
| :--- | :--- | :--- |
| `VITE_API_URL` | API base path (routes through Vite proxy in dev) | `/api` |

---

## 🚀 Installation & Startup (Windows PowerShell)

Open PowerShell in the project root directory:

### 1. Database Migration

```powershell
# Navigate to backend and install dependencies
cd backend
npm install

# Run database migrations
npm run db:migrate

# Verify database connection and schema integrity
npm run db:check
npm run db:verify-schema
```

### 2. Backend Startup

```powershell
# In backend directory (runs with nodemon on port 5000)
npm run dev
```

### 3. Frontend Startup

Open a **separate PowerShell window**:

```powershell
# Navigate to frontend and install dependencies
cd frontend
npm install

# Start the Vite development server on port 5173
npm run dev
```

The application is now accessible in your browser at:
👉 **`http://localhost:5173`**

> [!TIP]
> **Need test URLs or emails for a demo?** Check out [`DEMO_SAMPLES.md`](./DEMO_SAMPLES.md) for pre-built Safe, Suspicious, and Phishing copy-paste test cases.

---

## 🧪 Testing & Validation

PhishGuard includes automated test suites covering authentication, database schema, scan analysis engines, API security, and rate limiting:

```powershell
# Navigate to backend
cd backend

# Run the complete test suite (46 tests)
npm test

# Run code linter
npm run lint

# Run build verification
npm run build
```

To test the frontend production build:
```powershell
cd frontend
npm run build
```

---

## 🖥️ Frontend Interfaces

- **Landing Page (`/`):** Public showcase featuring CSS keyframe animations, intelligent precision hero messaging, instant Log In / Sign Up CTAs, feature benefit cards, custom PhishGuard brand logo, and responsive footer.
- **Dashboard (`/dashboard`):** Interactive scan submission interface with dedicated tabs for URL and Email heuristics, real-time status, and inline security report navigation.
- **Scan History (`/history`):** Filterable, searchable, paginated history with debounced input, date-range filters, verdict badges, desktop data table, and mobile card layout.
- **Security Report (`/history/:id`):** Deep inspection report displaying URL architecture, email indicators, risk meters, technical rationale, and the on-demand **AI Security Analysis** component.
- **Security Analytics (`/analytics`):** Real-time analytics dashboard with metric cards, Threat Distribution (donut chart), and Recent Activity (bar chart) powered by Recharts.
- **404 Page (`*`):** Branded, cybersecurity-themed not-found route.

---

## 📡 API Endpoints

Base URL: `http://localhost:5000` (Direct) or `/api` (via Frontend Proxy)

### Health
- `GET /api/health` — Checks API status and active PostgreSQL database connectivity.

### Authentication
- `POST /api/auth/register` — Registers a new user account (`name`, `email`, `password`).
- `POST /api/auth/login` — Authenticates user, returns access token and sets HttpOnly refresh cookie.
- `POST /api/auth/refresh` — Rotates session using HttpOnly cookie, returning a new access token.
- `GET /api/auth/me` — Returns the authenticated user profile (`Authorization: Bearer <token>`).
- `POST /api/auth/logout` — Revokes the active session and clears the refresh cookie.

### Scans (Authenticated)
- `POST /api/scans/url` — Scans an untrusted URL (`url`). Returns risk score, indicators, confidence.
- `POST /api/scans/email` — Scans email content (`subject`, `body`). Returns aggregated risk analysis.
- `GET /api/scans` — Lists user's scan history. Supports pagination (`page`, `limit`), sorting (`sortBy`, `sortOrder`), date ranges (`from`, `to`), search (`search`), and filtering (`scanType`, `verdict`).
- `GET /api/scans/:id` — Retrieves detailed scan results (slimmed in lists). Enforces IDOR protection (returns 404 for unauthorized access; admins permitted).
- `DELETE /api/scans/:id` — Deletes a single scan record and its analysis details. Enforces IDOR protection.
- `DELETE /api/scans` — Bulk clears the authenticated user's entire scan history.
- `GET /api/scans/analytics` — Computes user-scoped aggregated metrics directly inside PostgreSQL (supports `from`, `to`).

### AI Security Explanations (Authenticated & Rate-Limited)
- `POST /api/ai/explain-url` — Generates a structured AI explanation for a completed URL scan (`scanId`). Protected by `aiRateLimit` (5 requests / 15m) and server-side scan ownership validation.
- `POST /api/ai/explain-email` — Generates a structured AI explanation for a completed email scan (`scanId`), detailing social engineering techniques and indicator rationale.

---

## 🛡️ Security Notes

1. **Anti-SSRF:** Scanning is 100% static analysis. No outbound network requests are made to user-supplied URLs.
2. **AI Trust Boundary:** User-controlled content is strictly labeled untrusted data inside AI prompts. Gemini cannot alter verdicts or scores.
3. **API Key Isolation:** `GEMINI_API_KEY` is exclusively managed on the Express backend and is completely stripped from client builds.
4. **XSS Defense:** All AI explanations and detector indicators are rendered exclusively as inert React text nodes; `dangerouslySetInnerHTML` is prohibited.
2. **Timing Attack Protection:** Invalid email logins perform dummy bcrypt comparisons to prevent timing-based user enumeration.
3. **No Email Oracle:** Registration returns identical public response shapes even if an email is already registered.
4. **Session Revocation:** Refresh tokens are single-use; rotating a session revokes the previous session in PostgreSQL.
5. **IDOR Defense:** Accessing another user's scan returns `404 Not Found` rather than `403 Forbidden` to prevent ID space enumeration.
6. **Logging Redaction:** Passwords, tokens, cookies, authorization headers, and raw email bodies are automatically redacted from server logs.
7. **Rate Limiting:** IP-based rate limiting prevents brute-force login attempts and scan API flooding.
