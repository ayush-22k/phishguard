import pg from 'pg';
import { env, getDatabaseUrl } from '../config/env.js';

const { Pool } = pg;

let pool;

function isConnectionError(error) {
  return error?.code?.startsWith('08')
    || ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', '28P01', '3D000', '57P01'].includes(error?.code);
}

function createPool() {
  const databasePool = new Pool({
    connectionString: getDatabaseUrl(),
    application_name: 'phishguard-api',
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });

  databasePool.on('error', () => {
    // Do not include driver details here: they can expose connection configuration.
    console.error('Unexpected PostgreSQL pool error.');
  });

  return databasePool;
}

export function getPool() {
  pool ??= createPool();
  return pool;
}

export async function query(text, values = []) {
  try {
    return await getPool().query(text, values);
  } catch (error) {
    if (isConnectionError(error)) {
      console.error('PostgreSQL connection failed. Check DATABASE_URL and database availability.');
    }

    throw error;
  }
}

export async function withTransaction(callback) {
  let client;

  try {
    client = await getPool().connect();
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    if (isConnectionError(error)) {
      console.error('PostgreSQL connection failed. Check DATABASE_URL and database availability.');
    }
    if (client) {
      await client.query('ROLLBACK').catch(() => undefined);
    }
    throw error;
  } finally {
    client?.release();
  }
}

export async function closeDatabase() {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}

export const databaseConfig = Object.freeze({
  enabled: Boolean(env.databaseUrl),
});
