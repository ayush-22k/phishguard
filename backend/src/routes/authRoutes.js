import { Router } from 'express';
import { authController } from '../controllers/authController.js';
import { authenticate } from '../middleware/authMiddleware.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { authRateLimit } from '../middleware/rateLimiter.js';

const router = Router();

router.post('/register', authRateLimit, asyncHandler(authController.register));
router.post('/login', authRateLimit, asyncHandler(authController.login));
router.post('/refresh', authRateLimit, asyncHandler(authController.refresh));
router.get('/me', authenticate, asyncHandler(authController.me));
router.post('/logout', authenticate, asyncHandler(authController.logout));

export default router;
