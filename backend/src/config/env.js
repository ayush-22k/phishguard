import 'dotenv/config';

const port = Number.parseInt(process.env.PORT || '5000', 10);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be a valid TCP port number.');
}

export const env = Object.freeze({
  nodeEnv: process.env.NODE_ENV || 'development',
  port,
  clientUrl: process.env.CLIENT_URL || 'http://localhost:5173',
  databaseUrl: process.env.DATABASE_URL?.trim(),
  jwtSecret: process.env.JWT_SECRET?.trim(),
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET?.trim(),
  jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  jwtRefreshExpiresDays: process.env.JWT_REFRESH_EXPIRES_DAYS || '7',
  rateLimitGlobal: Number.parseInt(process.env.RATE_LIMIT_GLOBAL || '300', 10),
  rateLimitAuth: Number.parseInt(process.env.RATE_LIMIT_AUTH || '10', 10),
  rateLimitScan: Number.parseInt(process.env.RATE_LIMIT_SCAN || '50', 10),
  geminiApiKey: process.env.GEMINI_API_KEY?.trim(),
});

export function getDatabaseUrl() {
  if (!env.databaseUrl) {
    const error = new Error('DATABASE_URL must be set before using the database.');
    error.code = 'DATABASE_URL_MISSING';
    throw error;
  }

  return env.databaseUrl;
}

export function getAuthConfig() {
  if (!env.jwtSecret || env.jwtSecret.length < 32 || !env.jwtRefreshSecret || env.jwtRefreshSecret.length < 32) {
    const error = new Error('JWT_SECRET and JWT_REFRESH_SECRET must each be at least 32 characters.');
    error.code = 'AUTH_SECRETS_MISSING';
    throw error;
  }

  const refreshExpiresDays = Number.parseInt(env.jwtRefreshExpiresDays, 10);
  if (!Number.isInteger(refreshExpiresDays) || refreshExpiresDays < 1 || refreshExpiresDays > 30) {
    const error = new Error('JWT_REFRESH_EXPIRES_DAYS must be an integer between 1 and 30.');
    error.code = 'AUTH_CONFIG_INVALID';
    throw error;
  }

  return Object.freeze({
    accessSecret: env.jwtSecret,
    refreshSecret: env.jwtRefreshSecret,
    accessExpiresIn: env.jwtAccessExpiresIn,
    refreshExpiresMs: refreshExpiresDays * 24 * 60 * 60 * 1000,
  });
}

export function getGeminiConfig() {
  if (!env.geminiApiKey) {
    const error = new Error('Gemini API key is not configured.');
    error.code = 'GEMINI_CONFIG_MISSING';
    throw error;
  }
  
  return Object.freeze({
    apiKey: env.geminiApiKey,
  });
}
