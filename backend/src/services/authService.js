import bcrypt from 'bcryptjs';
import { authRepository } from '../repositories/authRepository.js';
import { hashSessionId, tokenService } from '../auth/tokenService.js';
import { validateLogin, validateRegistration } from '../auth/validation.js';
import { toSafeUser } from '../auth/user.js';
import { HttpError } from '../utils/httpError.js';

const passwordRounds = 12;
const dummyPasswordHash = bcrypt.hashSync('phishguard-auth-timing-padding', passwordRounds);

function invalidCredentials() {
  return new HttpError(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
}

function createCredentials(user, sessionId, tokens) {
  return {
    accessToken: tokens.signAccessToken(user, sessionId),
    refreshToken: tokens.signRefreshToken(user.id, sessionId),
    refreshExpiresAt: new Date(Date.now() + tokens.refreshExpiresMs),
  };
}

export function createAuthService({ repository = authRepository, tokens = tokenService, password = bcrypt } = {}) {
  async function register(input) {
    const registration = validateRegistration(input);
    const passwordHash = await password.hash(registration.password, passwordRounds);

    try {
      const user = await repository.createUser({
        name: registration.name,
        email: registration.email,
        passwordHash,
      });
      return { user: toSafeUser(user), registration };
    } catch (error) {
      if (error?.code === '23505') {
        // Keep the external response identical to avoid creating an email oracle.
        return { user: null, registration };
      }
      throw error;
    }
  }

  async function login(input) {
    const { email, password: plainPassword } = validateLogin(input);
    const user = await repository.findUserForLogin(email);
    const passwordMatches = await password.compare(plainPassword, user?.password_hash ?? dummyPasswordHash);

    if (!user || !passwordMatches) {
      throw invalidCredentials();
    }

    const sessionId = tokens.createSessionId();
    const credentials = createCredentials(user, sessionId, tokens);
    await repository.createSession({
      id: sessionId,
      userId: user.id,
      tokenHash: hashSessionId(sessionId),
      expiresAt: credentials.refreshExpiresAt,
    });
    await repository.updateLastLogin(user.id);

    return { user: toSafeUser({ ...user, last_login_at: new Date() }), ...credentials, sessionId };
  }

  async function refresh(refreshToken) {
    const payload = tokens.verifyRefreshToken(refreshToken);
    const session = await repository.findActiveSession(payload.sessionId, hashSessionId(payload.sessionId));
    if (!session || session.user_id !== payload.sub) {
      throw new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Authentication is required.');
    }

    const revoked = await repository.revokeSession(payload.sessionId);
    if (!revoked) {
      throw new HttpError(401, 'AUTHENTICATION_REQUIRED', 'Authentication is required.');
    }

    const user = toSafeUser(session);
    const sessionId = tokens.createSessionId();
    const credentials = createCredentials({ ...session, id: session.user_id }, sessionId, tokens);
    await repository.createSession({
      id: sessionId,
      userId: session.user_id,
      tokenHash: hashSessionId(sessionId),
      expiresAt: credentials.refreshExpiresAt,
    });

    return { user, ...credentials, sessionId };
  }

  async function logout(sessionId) {
    if (sessionId) {
      await repository.revokeSession(sessionId);
    }
  }

  return Object.freeze({ register, login, refresh, logout });
}

export const authService = createAuthService();
