import 'dotenv/config';

const port = Number.parseInt(process.env.PORT || '5000', 10);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be a valid TCP port number.');
}

export const env = Object.freeze({
  nodeEnv: process.env.NODE_ENV || 'development',
  port,
  clientUrl: process.env.CLIENT_URL || 'http://localhost:5173',
});
