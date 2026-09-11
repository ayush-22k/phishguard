# PhishGuard project state

## Current phase

- **Phase:** 1 — Project Architecture & Initial Setup
- **Status:** Complete

## Completed work

- Created frontend, backend, database, and docs project areas.
- Added a Vite-powered React, React Router, and Tailwind CSS placeholder interface with the initial PhishGuard visual identity.
- Added a modular Express API with `GET /api/health`.
- Added Helmet, environment-configured restricted CORS, global rate limiting, JSON size limits, and safe error responses.
- Added root environment template, Git ignore rules, and initial documentation.

## Project structure

- `frontend/`: React client; placeholder UI only.
- `backend/`: Express API; configuration, controller, route, middleware, and future-ready folders.
- `database/`: placeholder documentation; no schema or connection.
- `docs/`: reserved for expanded documentation.

## Important architectural decisions

- JavaScript only; Vite is the frontend build tool.
- Express serves REST APIs using a routes → controllers structure.
- API security middleware is centralized in `backend/src/app.js`.
- CORS origin is configured through `CLIENT_URL`; wildcard origins are not used.
- PostgreSQL will be accessed with parameterized SQL directly, without an ORM, in Phase 3.

## Database state

No database connection, migrations, schema, or tables exist yet. Neon PostgreSQL is reserved for Phase 3.

## API state

- Implemented: `GET /api/health`
- Not implemented: authentication, scans, detector services, history, admin APIs, audit logging.

## Environment variables

- Required now: `PORT`, `CLIENT_URL`, `NODE_ENV` (defaults permit local startup).
- Reserved: `DATABASE_URL`, `JWT_SECRET`, `JWT_REFRESH_SECRET`.

## Technology constraints

Uses React, Tailwind CSS, React Router, Axios, Node.js, Express, and npm. MongoDB, ORMs, TypeScript, Next.js, alternative frontend/state-management frameworks, Python backends, GraphQL, and Docker are not introduced.

## Security considerations

User input remains untrusted. No submitted URL or email is fetched, executed, or rendered. Secrets are environment-only. Helmet, rate limiting, restricted CORS, request-size limits, and safe errors are in place; authentication and deeper controls are pending later phases.

## Known limitations

- This phase has no authentication, persistence, scanners, dashboards, or admin features.
- Dependencies must be installed before running either application.
- Automated tests have not yet been added; runtime verification is required.

## Next phase

**Phase 2 — Authentication & Authorization**
