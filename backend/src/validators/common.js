import { HttpError } from '../utils/httpError.js';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export function validateEmail(email) {
  const normalized = normalizeEmail(email);
  if (!EMAIL_PATTERN.test(normalized) || normalized.length > 254) {
    throw new HttpError(400, 'INVALID_INPUT', 'Invalid email address.');
  }
  return normalized;
}

export function validateUrl(url) {
  if (typeof url !== 'string' || url.length > 2048) {
    throw new HttpError(400, 'INVALID_INPUT', 'Invalid URL.');
  }
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new HttpError(400, 'INVALID_INPUT', 'URL must use HTTP or HTTPS.');
    }
    return parsed.href;
  } catch {
    throw new HttpError(400, 'INVALID_INPUT', 'Invalid URL format.');
  }
}

export function validatePagination(query) {
  let page = 1;
  let limit = 20;

  if (query?.page !== undefined) {
    page = parseInt(query.page, 10);
    if (Number.isNaN(page) || page < 1) {
      throw new HttpError(400, 'INVALID_INPUT', 'Page must be a positive integer.');
    }
  }

  if (query?.limit !== undefined) {
    limit = parseInt(query.limit, 10);
    if (Number.isNaN(limit) || limit < 1 || limit > 100) {
      throw new HttpError(400, 'INVALID_INPUT', 'Limit must be between 1 and 100.');
    }
  }

  return { page, limit };
}

