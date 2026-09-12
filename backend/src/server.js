import app from './app.js';
import { env } from './config/env.js';
import { closeDatabase } from './database/index.js';

const server = app.listen(env.port, () => {
  console.log(`PhishGuard API listening on port ${env.port}`);
});

async function shutdown(signal) {
  console.log(`${signal} received; closing HTTP server.`);
  server.close(async () => {
    await closeDatabase();
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
