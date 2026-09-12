import { closeDatabase, query } from '../src/database/index.js';

async function checkDatabase() {
  const { rows } = await query('SELECT 1 AS connected');
  if (rows[0]?.connected !== 1) {
    throw new Error('Database connection check returned an unexpected result.');
  }

  console.log('PostgreSQL connection check passed.');
}

checkDatabase()
  .catch((error) => {
    const reason = error?.code === 'DATABASE_URL_MISSING'
      ? 'DATABASE_URL is not configured.'
      : `database error${error?.code ? ` (${error.code})` : ''}.`;
    console.error(`PostgreSQL connection check failed: ${reason}`);
    process.exitCode = 1;
  })
  .finally(closeDatabase);
