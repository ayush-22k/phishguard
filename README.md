# PhishGuard

PhishGuard is a cybersecurity web application being built to provide explainable phishing-risk analysis for URLs and email content.

## Current status

**Phase 1 — Project Architecture & Initial Setup: complete.** The repository contains a working React placeholder frontend and an Express health API. Authentication, persistence, detection, dashboards, and administration are planned—not yet implemented.

## Technology stack

- Frontend: React, JavaScript, Vite, Tailwind CSS, React Router, Axios
- Backend: Node.js, Express, JavaScript REST API
- Database (planned): Neon PostgreSQL via parameterized SQL queries
- Security foundation: Helmet, restricted CORS, express-rate-limit, environment-based configuration

## Architecture

`frontend/` is the React client. `backend/` is the Express API. `database/` will contain database documentation and migrations in Phase 3. Shared project documentation lives at the repository root and in `docs/`.

## Local setup

1. Copy `.env.example` to `backend/.env` and adjust `PORT` or `CLIENT_URL` only if needed.
2. In one terminal, run `cd backend`, `npm install`, then `npm run dev`.
3. In another terminal, run `cd frontend`, `npm install`, then `npm run dev`.
4. Open the URL printed by Vite (normally `http://localhost:5173`).
5. Request `http://localhost:5000/api/health` to verify the API.

## Phase-based development

PhishGuard is developed in constrained phases. Each phase is implemented, tested, documented, recorded in `PROJECT_STATE.md`, and reviewed before the next phase begins.
