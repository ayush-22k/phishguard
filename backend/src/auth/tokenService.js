import { createHash, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { getAuthConfig } from '../config/env.js';
import { HttpError } from '../utils/httpError.js';

const issuer = 'phishguard-api';
const audience = 'phishguard-client';

export function hashSessionId(sessionId) {
  return createHash('sha256').update(sessionId).digest('hex');
}

export function createTokenService(config = getAuthConfig()) {
  function signAccessToken(user, sessionId) {
    return jwt.sign(
      { role: user.role, sessionId, tokenType: 'access' },
      config.accessSecret,
      { subject: user.id, expiresIn: config.accessExpiresIn, issuer, audience },
    );
  }

  function signRefreshToken(userId, sessionId) {
    return jwt.sign(
      { sessionId, tokenType: 'refresh' },
      config.refreshSecret,
      { subject: userId, expiresIn: Math.floor(config.refreshExpiresMs / 1000), issuer, audience },
    );
  }

  function verifyAccessToken(token) {
    try {
      const payload = jwt.verify(token, config.accessSecret, { issuer, audience });
      if (payload.tokenType !== 'access' || typeof payload.sub !== 'string' || typeof payload.sessionId !== 'string') {
        throw new Error('Invalid access-token claims.');
      }
      return payload;
    } catch {
      throw new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Authentication is required.');
    }
  }

  function verifyRefreshToken(token) {
    try {
      const payload = jwt.verify(token, config.refreshSecret, { issuer, audience });
      if (payload.tokenType !== 'refresh' || typeof payload.sub !== 'string' || typeof payload.sessionId !== 'string') {
        throw new Error('Invalid refresh-token claims.');
      }
      return payload;
    } catch {
      throw new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Authentication is required.');
    }
  }

  return Object.freeze({
    createSessionId: randomUUID,
    signAccessToken,
    signRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
    refreshExpiresMs: config.refreshExpiresMs,
  });
}

export const tokenService = {
  createSessionId: randomUUID,
  signAccessToken: (...args) => createTokenService().signAccessToken(...args),
  signRefreshToken: (...args) => createTokenService().signRefreshToken(...args),
  verifyAccessToken: (...args) => createTokenService().verifyAccessToken(...args),
  verifyRefreshToken: (...args) => createTokenService().verifyRefreshToken(...args),
  get refreshExpiresMs() {
    return getAuthConfig().refreshExpiresMs;
  },
};
