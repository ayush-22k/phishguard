# Security policy and architecture

## Current foundation

Phase 1 configures Helmet security headers, CORS restricted to the configured `CLIENT_URL`, a global API rate limit, JSON request-size limits, and safe production-style error responses. Configuration is read from environment variables; secrets are never hardcoded.

## Handling untrusted input

All future URL and email submissions are untrusted data. PhishGuard must never execute submitted URLs, follow them automatically, download arbitrary content, execute attachments, or render untrusted HTML. Validation and sanitization will precede every future analysis.

## Planned controls

Authentication, authorization, bcrypt password hashing, JWT and refresh-token handling, role enforcement, PostgreSQL parameterized queries, audit logging, endpoint-specific abuse controls, and security testing will be introduced in their designated phases. Security hardening continues through Phase 9.

## Secret handling

Store credentials and cryptographic secrets only in local or deployed environment configuration. `.env` files are ignored by Git; `.env.example` includes names only. Immediately rotate any secret accidentally committed to source control.

## Reporting concerns

Until a formal disclosure process is published, do not include sensitive exploit details in public issues. Contact the repository maintainer privately with a concise reproduction and impact summary.
