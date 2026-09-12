import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const testDirectory = dirname(fileURLToPath(import.meta.url));
const migrationPath = join(testDirectory, '..', '..', 'database', 'migrations', '001_initial_schema.sql');
const migration = await readFile(migrationPath, 'utf8');
const sessionsMigrationPath = join(testDirectory, '..', '..', 'database', 'migrations', '002_auth_sessions.sql');
const sessionsMigration = await readFile(sessionsMigrationPath, 'utf8');

test('initial migration defines the required database foundation', () => {
  assert.match(migration, /CREATE TABLE users/i);
  assert.match(migration, /email VARCHAR\(254\) NOT NULL UNIQUE/i);
  assert.match(migration, /password_hash TEXT NOT NULL/i);
  assert.match(migration, /CREATE TABLE scans/i);
  assert.match(migration, /REFERENCES users\(id\) ON DELETE CASCADE/i);
  assert.match(migration, /CREATE TABLE scan_results/i);
  assert.match(migration, /scan_id UUID PRIMARY KEY REFERENCES scans\(id\) ON DELETE CASCADE/i);
  assert.match(migration, /CREATE INDEX idx_scans_user_id/i);
  assert.match(migration, /CREATE INDEX idx_scans_created_at/i);
  assert.match(migration, /CREATE INDEX idx_scans_scan_type/i);
  assert.match(migration, /CREATE INDEX idx_scans_classification/i);
  assert.match(sessionsMigration, /CREATE TABLE auth_sessions/i);
  assert.match(sessionsMigration, /REFERENCES users\(id\) ON DELETE CASCADE/i);
  assert.match(sessionsMigration, /token_hash CHAR\(64\) NOT NULL UNIQUE/i);
});
