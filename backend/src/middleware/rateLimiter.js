import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

function createRateLimiter(limit, message) {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
      success: false,
      error: {
        code: 'TOO_MANY_REQUESTS',
        message,
      },
    },
  });
}

export const globalRateLimit = createRateLimiter(
  env.rateLimitGlobal,
  'Too many requests from this IP, please try again later.'
);

export const authRateLimit = createRateLimiter(
  env.rateLimitAuth,
  'Too many authentication attempts. Please try again later.'
);

export const scanRateLimit = createRateLimiter(
  env.rateLimitScan,
  'Too many scan requests. Please try again later.'
);

export const aiRateLimit = createRateLimiter(
  5, // Strict limit for AI explanation requests: 5 per 15 minutes per IP
  'AI analysis rate limit exceeded. Please try again later.'
);

