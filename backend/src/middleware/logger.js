import { env } from '../config/env.js';

const SENSITIVE_FIELDS = new Set([
  'password',
  'token',
  'accesstoken',
  'refreshtoken',
  'authorization',
  'cookie',
  'body',
  'emailbody',
  'secret',
  'credential',
  'apikey',
  'url',
  'subject',
  'subjectpreview',
]);

function redact(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(redact);
  
  const redacted = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redact(value);
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}

export function requestLogger(request, response, next) {
  const start = Date.now();
  
  response.on('finish', () => {
    const duration = Date.now() - start;
    if (env.nodeEnv !== 'test') {
      const logEntry = {
        timestamp: new Date().toISOString(),
        method: request.method,
        url: request.originalUrl,
        status: response.statusCode,
        durationMs: duration,
        ip: request.ip,
        userAgent: request.get('user-agent'),
      };
      
      // Optionally log safe body parameters (like email for registration)
      if (request.method !== 'GET' && request.body && Object.keys(request.body).length > 0) {
         logEntry.body = redact(request.body);
      }
      
      console.log(JSON.stringify(logEntry));
    }
  });
  
  next();
}

