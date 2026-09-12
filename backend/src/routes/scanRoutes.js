import { Router } from 'express';
import { scanController } from '../controllers/scanController.js';
import { authenticate } from '../middleware/authMiddleware.js';
import { scanRateLimit } from '../middleware/rateLimiter.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const router = Router();

// All scan endpoints require authentication and scan-specific rate limiting
router.use(authenticate);
router.use(scanRateLimit);

router.post('/url', asyncHandler(scanController.scanUrl));
router.post('/email', asyncHandler(scanController.scanEmail));
router.get('/analytics', asyncHandler(scanController.getAnalytics));
router.get('/', asyncHandler(scanController.getHistory));
router.get('/:id', asyncHandler(scanController.getScanById));
router.delete('/', asyncHandler(scanController.clearHistory));
router.delete('/:id', asyncHandler(scanController.deleteScan));

export default router;
