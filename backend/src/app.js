import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { env } from './config/env.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import authRoutes from './routes/authRoutes.js';
import healthRoutes from './routes/healthRoutes.js';
import scanRoutes from './routes/scanRoutes.js';
import aiRoutes from './routes/aiRoutes.js';

import { globalRateLimit } from './middleware/rateLimiter.js';

import { requestLogger } from './middleware/logger.js';

const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(requestLogger);
app.use(helmet());
app.use(cors({
  origin: env.clientUrl,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '100kb' }));
app.use(globalRateLimit);

app.use('/api', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/ai', aiRoutes);
app.use(notFoundHandler);
app.use(errorHandler);

export default app;
