import assert from 'node:assert/strict';
import bcrypt from 'bcryptjs';
import test from 'node:test';
import { createAuthController } from '../src/controllers/authController.js';
import { createAuthenticate, requireRole } from '../src/middleware/authMiddleware.js';
import { createAuthService } from '../src/services/authService.js';
import { createTokenService, hashSessionId } from '../src/auth/tokenService.js';

function createRepository() {
  const users = new Map();
  const sessions = new Map();
  let nextId = 1;

  return {
    users,
    sessions,
    async createUser({ name, email, passwordHash }) {
      if (users.has(email)) {
        const error = new Error('duplicate');
        error.code = '23505';
        throw error;
      }
      const user = {
        id: `user-${nextId++}`,
        name,
        email,
        password_hash: passwordHash,
        role: 'user',
        is_verified: false,
        created_at: new Date(),
        updated_at: new Date(),
        last_login_at: null,
      };
      users.set(email, user);
      return user;
    },
    async findUserForLogin(email) {
      return users.get(email) ?? null;
    },
    async updateLastLogin(id) {
      for (const user of users.values()) {
        if (user.id === id) user.last_login_at = new Date();
      }
    },
    async createSession({ id, userId, tokenHash, expiresAt }) {
      sessions.set(id, { id, user_id: userId, token_hash: tokenHash, expires_at: expiresAt, revoked_at: null });
    },
    async findActiveSession(sessionId, tokenHash) {
      const session = sessions.get(sessionId);
      if (!session || session.revoked_at || session.expires_at <= new Date() || session.token_hash !== tokenHash) return null;
      const user = [...users.values()].find((item) => item.id === session.user_id);
      return user ? { ...user, user_id: session.user_id } : null;
    },
    async touchSession() {},
    async revokeSession(sessionId) {
      const session = sessions.get(sessionId);
      if (!session || session.revoked_at) return false;
      session.revoked_at = new Date();
      return true;
    },
  };
}

function createResponse() {
  return {
    statusCode: null,
    body: null,
    cookies: [],
    cleared: [],
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
    cookie(...args) { this.cookies.push(args); return this; },
    clearCookie(...args) { this.cleared.push(args); return this; },
    send() { return this; },
  };
}

function createFixture() {
  const repository = createRepository();
  const tokens = createTokenService({
    accessSecret: 'a'.repeat(48),
    refreshSecret: 'b'.repeat(48),
    accessExpiresIn: '15m',
    refreshExpiresMs: 60 * 60 * 1000,
  });
  return { repository, tokens, service: createAuthService({ repository, tokens }) };
}

test('registration validates input, hashes passwords, and hides duplicate-email details', async () => {
  const { repository, service } = createFixture();
  const first = await service.register({ name: ' Ada Lovelace ', email: ' ADA@Example.COM ', password: 'long-enough-password' });

  assert.equal(first.user.email, 'ada@example.com');
  assert.equal(first.user.role, 'USER');
  assert.notEqual(repository.users.get('ada@example.com').password_hash, 'long-enough-password');
  assert.equal(await bcrypt.compare('long-enough-password', repository.users.get('ada@example.com').password_hash), true);

  const duplicate = await service.register({ name: 'Ada Lovelace', email: 'ada@example.com', password: 'long-enough-password' });
  assert.equal(duplicate.user, null);

  const controller = createAuthController(service);
  const registrationResponse = createResponse();
  await controller.register({ body: { name: 'New User', email: 'new@example.com', password: 'long-enough-password' } }, registrationResponse);
  const duplicateResponse = createResponse();
  await controller.register({ body: { name: 'New User', email: 'new@example.com', password: 'long-enough-password' } }, duplicateResponse);
  assert.equal(registrationResponse.statusCode, 201);
  assert.deepEqual(registrationResponse.body, duplicateResponse.body);

  await assert.rejects(
    service.register({ name: '', email: 'not-an-email', password: 'short' }),
    { statusCode: 400, code: 'INVALID_INPUT' },
  );
});

test('login issues credentials, updates login time, and uses generic invalid-credential errors', async () => {
  const { repository, service } = createFixture();
  await service.register({ name: 'Grace Hopper', email: 'grace@example.com', password: 'long-enough-password' });

  const result = await service.login({ email: 'GRACE@example.com', password: 'long-enough-password' });
  assert.equal(result.user.email, 'grace@example.com');
  assert.match(result.accessToken, /^[\w-]+\.[\w-]+\.[\w-]+$/);
  assert.match(result.refreshToken, /^[\w-]+\.[\w-]+\.[\w-]+$/);
  assert.ok(repository.sessions.has(result.sessionId));
  assert.ok(repository.users.get('grace@example.com').last_login_at);

  await assert.rejects(
    service.login({ email: 'missing@example.com', password: 'long-enough-password' }),
    { statusCode: 401, code: 'INVALID_CREDENTIALS' },
  );
  await assert.rejects(
    service.login({ email: 'grace@example.com', password: 'wrong-password-value' }),
    { statusCode: 401, code: 'INVALID_CREDENTIALS' },
  );
});

test('authenticated user context, logout, authorization, and invalid credentials are enforced', async () => {
  const { repository, tokens, service } = createFixture();
  await service.register({ name: 'Linus Torvalds', email: 'linus@example.com', password: 'long-enough-password' });
  const login = await service.login({ email: 'linus@example.com', password: 'long-enough-password' });
  const authenticate = createAuthenticate({ repository, tokens });
  const request = { headers: { authorization: `Bearer ${login.accessToken}` } };
  let middlewareError;
  await authenticate(request, {}, (error) => { middlewareError = error; });
  assert.equal(middlewareError, undefined);
  assert.equal(request.user.email, 'linus@example.com');

  const controller = createAuthController(service);
  const meResponse = createResponse();
  await controller.me(request, meResponse);
  assert.equal(meResponse.statusCode, 200);
  assert.equal(meResponse.body.data.user.email, 'linus@example.com');

  const noCredentialsRequest = { headers: {} };
  await authenticate(noCredentialsRequest, {}, (error) => { middlewareError = error; });
  assert.equal(middlewareError.statusCode, 401);

  const blocked = requireRole('ADMIN');
  blocked(request, {}, (error) => { middlewareError = error; });
  assert.equal(middlewareError.statusCode, 403);
  request.user = { ...request.user, role: 'ADMIN' };
  blocked(request, {}, (error) => { middlewareError = error; });
  assert.equal(middlewareError, undefined);

  const response = createResponse();
  await controller.logout({ auth: { sessionId: login.sessionId } }, response);
  assert.equal(response.statusCode, 204);
  assert.equal(response.cleared.length, 1);
  assert.equal(repository.sessions.get(login.sessionId).revoked_at instanceof Date, true);

  await authenticate({ headers: { authorization: `Bearer ${login.accessToken}` } }, {}, (error) => { middlewareError = error; });
  assert.equal(middlewareError.statusCode, 401);
  assert.equal(hashSessionId(login.sessionId).length, 64);
});

test('expired access tokens are rejected', async () => {
  const repository = createRepository();
  const tokens = createTokenService({
    accessSecret: 'a'.repeat(48),
    refreshSecret: 'b'.repeat(48),
    accessExpiresIn: '-1s',
    refreshExpiresMs: 60 * 60 * 1000,
  });
  const sessionId = tokens.createSessionId();
  const user = { id: 'expired-user', name: 'Expired User', email: 'expired@example.com', role: 'user', is_verified: false };
  repository.users.set(user.email, user);
  await repository.createSession({ id: sessionId, userId: user.id, tokenHash: hashSessionId(sessionId), expiresAt: new Date(Date.now() + 60_000) });
  const authenticate = createAuthenticate({ repository, tokens });
  const accessToken = tokens.signAccessToken(user, sessionId);
  let middlewareError;
  await authenticate({ headers: { authorization: `Bearer ${accessToken}` } }, {}, (error) => { middlewareError = error; });
  assert.equal(middlewareError.statusCode, 401);
});

test('refresh token rotates session, issues new tokens, and prevents token reuse', async () => {
  const { repository, service } = createFixture();
  await service.register({ name: 'Margaret Hamilton', email: 'margaret@example.com', password: 'long-enough-password' });
  const login = await service.login({ email: 'margaret@example.com', password: 'long-enough-password' });

  // 1. First refresh should succeed and rotate session
  const refreshed = await service.refresh(login.refreshToken);
  assert.equal(refreshed.user.email, 'margaret@example.com');
  assert.ok(refreshed.accessToken);
  assert.ok(refreshed.refreshToken);
  assert.notEqual(refreshed.sessionId, login.sessionId);

  // 2. The old session must be marked as revoked
  const oldSession = repository.sessions.get(login.sessionId);
  assert.ok(oldSession.revoked_at instanceof Date);

  // 3. Reusing the old refresh token MUST fail with 401 (rotation protection)
  await assert.rejects(
    service.refresh(login.refreshToken),
    { statusCode: 401, code: 'AUTHENTICATION_REQUIRED' }
  );

  // 4. Using the newly issued refresh token must succeed
  const refreshedAgain = await service.refresh(refreshed.refreshToken);
  assert.equal(refreshedAgain.user.email, 'margaret@example.com');
  assert.notEqual(refreshedAgain.sessionId, refreshed.sessionId);
});
