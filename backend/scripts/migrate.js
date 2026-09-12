import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closeDatabase, withTransaction } from '../src/database/index.js';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const migrationsDirectory = join(scriptDirectory, '..', '..', 'database', 'migrations');

async function loadMigrations() {
  const files = (await readdir(migrationsDirectory))
    .filter((file) => /^\d{3}_[a-z0-9_]+\.sql$/i.test(file))
    .sort();

  return Promise.all(files.map(async (name) => {
    const sql = await readFile(join(migrationsDirectory, name), 'utf8');
    return {
      name,
      sql,
      checksum: createHash('sha256').update(sql).digest('hex'),
    };
  }));
}

async function migrate() {
  const migrations = await loadMigrations();

  await withTransaction(async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name TEXT PRIMARY KEY,
        checksum CHAR(64) NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const { rows: applied } = await client.query(
      'SELECT name, checksum FROM schema_migrations ORDER BY name',
    );
    const appliedByName = new Map(applied.map((migration) => [migration.name, migration.checksum]));

    for (const migration of migrations) {
      const storedChecksum = appliedByName.get(migration.name);
      if (storedChecksum) {
        if (storedChecksum !== migration.checksum) {
          throw new Error(`Migration checksum mismatch for ${migration.name}. Create a new migration instead of editing an applied one.`);
        }
        continue;
      }

      await client.query(migration.sql);
      await client.query(
        'INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)',
        [migration.name, migration.checksum],
      );
      console.log(`Applied migration ${migration.name}`);
    }
  });

  console.log('Database migrations are up to date.');
}

migrate()
  .catch((error) => {
    const reason = error?.code === 'DATABASE_URL_MISSING'
      ? 'DATABASE_URL is not configured.'
      : `database error${error?.code ? ` (${error.code})` : ''}.`;
    console.error(`Database migration failed: ${reason}`);
    process.exitCode = 1;
  })
  .finally(closeDatabase);
