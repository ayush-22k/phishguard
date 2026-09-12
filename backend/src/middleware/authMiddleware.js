import { hashSessionId, tokenService } from '../auth/tokenService.js';
import { toSafeUser } from '../auth/user.js';
import { authRepository } from '../repositories/authRepository.js';
import { HttpError } from '../utils/httpError.js';

export const ROLES = Object.freeze({ USER: 'USER', ADMIN: 'ADMIN' });

function extractBearerToken(header) {
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}

export function createAuthenticate({ repository = authRepository, tokens = tokenService } = {}) {
  return async function authenticate(request, _response, next) {
    try {
      const credential = extractBearerToken(request.get?.('authorization') ?? request.headers?.authorization);
      if (!credential) {
        throw new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Authentication is required.');
      }

      const payload = tokens.verifyAccessToken(credential);
      const session = await repository.findActiveSession(payload.sessionId, hashSessionId(payload.sessionId));
      if (!session || session.user_id !== payload.sub) {
        throw new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Authentication is required.');
      }

      await repository.touchSession(payload.sessionId);
      request.auth = Object.freeze({ userId: payload.sub, sessionId: payload.sessionId });
      request.user = toSafeUser(session);
      return next();
    } catch (error) {
      return next(error instanceof HttpError
        ? error
        : new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Authentication is required.'));
    }
  };
}

export const authenticate = createAuthenticate();

export function requireRole(...roles) {
  const permittedRoles = new Set(roles.map((role) => String(role).toUpperCase()));
  return function authorize(request, _response, next) {
    if (!request.user || !permittedRoles.has(request.user.role)) {
      return next(new HttpError(403, 'FORBIDDEN', 'You do not have permission to perform this action.'));
    }
    return next();
  };
}
