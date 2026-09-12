import { query } from '../database/index.js';

const safeColumns = `id, name, email, role, is_verified, created_at, updated_at, last_login_at`;

export const authRepository = Object.freeze({
  async createUser({ name, email, passwordHash }) {
    const result = await query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING ${safeColumns}`,
      [name, email, passwordHash],
    );
    return result.rows[0];
  },

  async findUserForLogin(email) {
    const result = await query(
      `SELECT ${safeColumns}, password_hash FROM users WHERE email = $1`,
      [email],
    );
    return result.rows[0] ?? null;
  },

  async findSafeUserById(id) {
    const result = await query(`SELECT ${safeColumns} FROM users WHERE id = $1`, [id]);
    return result.rows[0] ?? null;
  },

  async updateLastLogin(id) {
    await query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [id]);
  },

  async createSession({ id, userId, tokenHash, expiresAt }) {
    await query(
      `INSERT INTO auth_sessions (id, user_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [id, userId, tokenHash, expiresAt],
    );
  },

  async findActiveSession(sessionId, tokenHash) {
    const result = await query(
      `SELECT s.id AS session_id, s.user_id, s.expires_at, s.revoked_at, u.id, u.name, u.email, u.role,
              u.is_verified, u.created_at, u.updated_at, u.last_login_at
       FROM auth_sessions s
       INNER JOIN users u ON u.id = s.user_id
       WHERE s.id = $1 AND s.token_hash = $2 AND s.revoked_at IS NULL AND s.expires_at > NOW()`,
      [sessionId, tokenHash],
    );
    return result.rows[0] ?? null;
  },

  async touchSession(sessionId) {
    await query('UPDATE auth_sessions SET last_used_at = NOW() WHERE id = $1 AND revoked_at IS NULL', [sessionId]);
  },

  async revokeSession(sessionId) {
    const result = await query('UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL', [sessionId]);
    return result.rowCount > 0;
  },
});
