import crypto from 'node:crypto';
import { analyzeUrl } from '../engine/url/index.js';
import { analyzeEmail } from '../engine/email/index.js';
import { scanRepository } from '../repositories/scanRepository.js';
import { HttpError } from '../utils/httpError.js';

function toDbClassification(classification) {
  const upper = String(classification).toUpperCase();
  if (upper === 'SAFE' || upper === 'BENIGN') return 'benign';
  if (upper === 'SUSPICIOUS') return 'suspicious';
  if (upper === 'MALICIOUS' || upper === 'PHISHING') return 'phishing';
  return 'suspicious';
}

function computeHash(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function formatConfidence(confidenceNumber) {
  const ratio = Math.min(1, Math.max(0, confidenceNumber / 100));
  return ratio.toFixed(4);
}

function formatScanOutput(record) {
  const input = record.scan_type === 'email' 
    ? (record.metadata?.subjectPreview || '') 
    : (record.metadata?.targetUrl || '');

  return {
    id: record.id,
    scanId: record.id,
    type: record.scan_type,
    scanType: String(record.scan_type).toUpperCase(),
    input,
    normalizedInput: input,
    classification: record.classification,
    verdict: String(record.classification).toUpperCase(),
    riskScore: record.risk_score,
    confidence: Number(record.confidence),
    indicators: record.indicators ?? [],
    detectionReasons: record.indicators ?? [],
    explanation: record.explanation,
    metadata: record.metadata ?? {},
    createdAt: record.created_at,
  };
}

function formatScanListOutput(record) {
  const input = record.scan_type === 'email' 
    ? (record.metadata?.subjectPreview || '') 
    : (record.metadata?.targetUrl || '');

  return {
    id: record.id,
    scanType: String(record.scan_type).toUpperCase(),
    type: record.scan_type,
    input,
    riskScore: record.risk_score,
    verdict: String(record.classification).toUpperCase(),
    classification: record.classification,
    confidence: Number(record.confidence),
    createdAt: record.created_at,
  };
}

export const scanService = Object.freeze({
  async scanUrl(userId, rawUrl) {
    const analysis = analyzeUrl(rawUrl);

    if (!analysis.isValid) {
      throw new HttpError(400, 'INVALID_URL', analysis.explanation || 'Invalid or malformed URL structure.');
    }

    const inputHash = computeHash(analysis.url.normalized || rawUrl);
    const dbClassification = toDbClassification(analysis.classification);
    const confidence = formatConfidence(analysis.confidence);

    const scan = await scanRepository.createScan({
      userId,
      scanType: 'url',
      inputHash,
      riskScore: analysis.riskScore,
      classification: dbClassification,
      confidence,
      analysis: analysis.features || {},
      indicators: analysis.indicators,
      explanation: analysis.explanation,
      metadata: {
        targetUrl: analysis.url.normalized || rawUrl,
        protocol: analysis.url.protocol,
        hostname: analysis.url.hostname,
      },
    });

    return formatScanOutput(scan);
  },

  async scanEmail(userId, { subject = '', body = '' }) {
    const analysis = analyzeEmail({ subject, body });

    if (!analysis.isValid) {
      throw new HttpError(400, 'INVALID_INPUT', analysis.explanation || 'Invalid email content.');
    }

    const inputHash = computeHash(`${subject}\n${body}`);
    const dbClassification = toDbClassification(analysis.classification);
    const confidence = formatConfidence(analysis.confidence);

    const combinedIndicators = [
      ...analysis.emailIndicators,
      ...analysis.urlIndicators,
    ];

    const metadata = {
      subjectPreview: subject ? subject.slice(0, 100) : '',
      urlsFound: analysis.metrics.urlsFound,
      semanticScore: analysis.metrics.semanticScore,
      highestUrlScore: analysis.metrics.highestUrlScore,
    };

    const scan = await scanRepository.createScan({
      userId,
      scanType: 'email',
      inputHash,
      riskScore: analysis.riskScore,
      classification: dbClassification,
      confidence,
      analysis: {
        metrics: analysis.metrics,
        emailIndicators: analysis.emailIndicators,
        urlIndicators: analysis.urlIndicators,
      },
      indicators: combinedIndicators,
      explanation: analysis.explanation,
      metadata,
    });

    const output = formatScanOutput(scan);
    return {
      ...output,
      emailIndicators: analysis.emailIndicators,
      urlIndicators: analysis.urlIndicators,
      metrics: analysis.metrics,
    };
  },

  async getHistory(user, queryOptions) {
    const result = await scanRepository.findScansByUser(user.id, queryOptions);
    return {
      scans: result.scans.map(formatScanListOutput),
      pagination: {
        total: result.total,
        page: result.page,
        limit: result.limit,
        totalPages: result.totalPages,
        hasNextPage: result.page < result.totalPages,
        hasPreviousPage: result.page > 1
      },
    };
  },

  async getScanById(user, scanId) {
    const scan = await scanRepository.findScanById(scanId);
    if (!scan) {
      throw new HttpError(404, 'SCAN_NOT_FOUND', 'Scan not found.');
    }

    if (scan.user_id !== user.id && user.role !== 'ADMIN') {
      throw new HttpError(404, 'SCAN_NOT_FOUND', 'Scan not found.');
    }

    return {
      ...formatScanOutput(scan),
      analysis: scan.analysis ?? {},
      detectionResult: scan.analysis ?? {},
    };
  },

  async deleteScan(user, scanId) {
    const scan = await scanRepository.findScanById(scanId);
    if (!scan) {
      throw new HttpError(404, 'SCAN_NOT_FOUND', 'Scan not found.');
    }

    if (scan.user_id !== user.id && user.role !== 'ADMIN') {
      throw new HttpError(404, 'SCAN_NOT_FOUND', 'Scan not found.');
    }

    await scanRepository.deleteScanById(scanId);
    return {
      success: true,
      message: 'Scan deleted successfully.',
    };
  },

  async clearHistory(user) {
    const deletedCount = await scanRepository.deleteAllScansByUser(user.id);
    return {
      success: true,
      message: 'Scan history cleared successfully.',
      deletedCount,
    };
  },

  async getAnalytics(user, options = {}) {
    const userId = typeof user === 'object' && user !== null ? user.id : user;
    if (!userId) {
      throw new HttpError(400, 'USER_ID_REQUIRED', 'User ID is required.');
    }
    return await scanRepository.getScanAnalytics(userId, options);
  },
});
