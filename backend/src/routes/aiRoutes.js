import { Router } from 'express';
import { aiController } from '../controllers/aiController.js';
import { authenticate } from '../middleware/authMiddleware.js';
import { aiRateLimit } from '../middleware/rateLimiter.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const router = Router();

// Protect AI endpoints with authentication and strict rate limiting
router.use(authenticate);
router.use(aiRateLimit);

router.post('/explain-url', asyncHandler(aiController.explainUrl));
router.post('/explain-email', asyncHandler(aiController.explainEmail));

export default router;

