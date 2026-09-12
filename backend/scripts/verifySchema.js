import { closeDatabase, query } from '../src/database/index.js';

const requiredTables = ['users', 'scans', 'scan_results', 'auth_sessions'];

async function verifySchema() {
  const { rows } = await query(
    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = ANY($1::text[])",
    [requiredTables],
  );
  const present = new Set(rows.map((row) => row.tablename));
  const missing = requiredTables.filter((table) => !present.has(table));

  if (missing.length > 0) {
    throw new Error('Required schema tables are missing.');
  }

  console.log('Required database tables are present.');
}

verifySchema()
  .catch((error) => {
    const reason = error?.code === 'DATABASE_URL_MISSING'
      ? 'DATABASE_URL is not configured.'
      : `database error${error?.code ? ` (${error.code})` : ''}.`;
    console.error(`Database schema verification failed: ${reason}`);
    process.exitCode = 1;
  })
  .finally(closeDatabase);
