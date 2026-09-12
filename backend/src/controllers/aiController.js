import { scanService } from '../services/scanService.js';
import { generateURLExplanation, generateEmailExplanation } from '../services/geminiService.js';
import { HttpError } from '../utils/httpError.js';

export const aiController = Object.freeze({
  async explainUrl(request, response) {
    const { scanId } = request.body;

    if (!scanId || typeof scanId !== 'string') {
      throw new HttpError(400, 'INVALID_INPUT', 'scanId is required and must be a string.');
    }

    // scanService.getScanById handles the DB lookup and authorization checks
    // Throws 404 if not found or if the user doesn't own it.
    const scan = await scanService.getScanById(request.user, scanId);

    if (scan.type !== 'url') {
      throw new HttpError(400, 'INVALID_SCAN_TYPE', 'Only URL scans are supported for this explanation feature.');
    }

    const { verdict, riskScore, indicators } = scan;

    const explanation = await generateURLExplanation({
      verdict,
      riskScore,
      indicators
    });

    return response.status(200).json({
      success: true,
      data: explanation,
    });
  },

  async explainEmail(request, response) {
    const { scanId } = request.body;

    if (!scanId || typeof scanId !== 'string') {
      throw new HttpError(400, 'INVALID_INPUT', 'scanId is required and must be a string.');
    }

    // scanService.getScanById handles the DB lookup and authorization checks
    // Throws 404 if not found or if the user doesn't own it.
    const scan = await scanService.getScanById(request.user, scanId);

    if (scan.type !== 'email') {
      throw new HttpError(400, 'INVALID_SCAN_TYPE', 'Only email scans are supported for this explanation feature.');
    }

    const { verdict, riskScore, indicators } = scan;

    const explanation = await generateEmailExplanation({
      verdict,
      riskScore,
      indicators
    });

    return response.status(200).json({
      success: true,
      data: explanation,
    });
  },
});

