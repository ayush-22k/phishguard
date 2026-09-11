# PhishGuard API

Base URL during local development: `http://localhost:5000`

## Health check

### `GET /api/health`

Confirms that the Phase 1 Express service is available.

Authentication: not required.

Success response (`200`):

```json
{
  "success": true,
  "message": "PhishGuard API is running"
}
```

Unknown routes return a safe `404` JSON error. Authentication, scan, detection, history, and admin endpoints are planned for later phases and are not available yet.
