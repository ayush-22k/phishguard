import { scanService } from '../services/scanService.js';
import {
  validateUrlScanInput,
  validateEmailScanInput,
  validateScanQuery,
  validateScanIdParam,
} from '../validators/scanValidators.js';

export const scanController = Object.freeze({
  async scanUrl(req, res) {
    const { url } = validateUrlScanInput(req.body);
    const result = await scanService.scanUrl(req.user.id, url);
    res.status(200).json({
      success: true,
      data: result,
    });
  },

  async scanEmail(req, res) {
    const input = validateEmailScanInput(req.body);
    const result = await scanService.scanEmail(req.user.id, input);
    res.status(200).json({
      success: true,
      data: result,
    });
  },

  async getHistory(req, res) {
    const options = validateScanQuery(req.query);
    const result = await scanService.getHistory(req.user, options);
    res.status(200).json({
      success: true,
      data: result,
    });
  },

  async getScanById(req, res) {
    const scanId = validateScanIdParam(req.params);
    const result = await scanService.getScanById(req.user, scanId);
    res.status(200).json({
      success: true,
      data: result,
    });
  },

  async deleteScan(req, res) {
    const scanId = validateScanIdParam(req.params);
    const result = await scanService.deleteScan(req.user, scanId);
    res.status(200).json({
      success: true,
      data: result,
    });
  },

  async clearHistory(req, res) {
    const result = await scanService.clearHistory(req.user);
    res.status(200).json({
      success: true,
      data: result,
    });
  },

  async getAnalytics(req, res) {
    const { from, to } = req.query;
    
    // Optional basic date validation
    let fromIso = undefined;
    let toIso = undefined;

    if (from) {
      fromIso = new Date(from);
      if (isNaN(fromIso.getTime())) {
        fromIso = undefined;
      } else {
        fromIso = fromIso.toISOString();
      }
    }

    if (to) {
      toIso = new Date(to);
      if (isNaN(toIso.getTime())) {
        toIso = undefined;
      } else {
        toIso = toIso.toISOString();
      }
    }

    const result = await scanService.getAnalytics(req.user, { from: fromIso, to: toIso });
    res.status(200).json({
      success: true,
      data: result,
    });
  }
});

