import { HttpError } from '../utils/httpError.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateUrlScanInput(body) {
  if (!body || typeof body !== 'object') {
    throw new HttpError(400, 'INVALID_INPUT', 'Request body must be a valid JSON object.');
  }

  const { url } = body;
  if (typeof url !== 'string' || !url.trim()) {
    throw new HttpError(400, 'INVALID_INPUT', 'A valid URL string is required.');
  }

  const trimmed = url.trim();
  if (trimmed.length > 4096) {
    throw new HttpError(400, 'INVALID_INPUT', 'URL exceeds maximum length of 4096 characters.');
  }

  return { url: trimmed };
}

export function validateEmailScanInput(body) {
  if (!body || typeof body !== 'object') {
    throw new HttpError(400, 'INVALID_INPUT', 'Request body must be a valid JSON object.');
  }

  const { subject, body: emailBody } = body;
  const hasSubject = typeof subject === 'string' && subject.trim().length > 0;
  const hasBody = typeof emailBody === 'string' && emailBody.trim().length > 0;

  if (!hasSubject && !hasBody) {
    throw new HttpError(400, 'INVALID_INPUT', 'Email subject or body is required.');
  }

  if (subject !== undefined && typeof subject !== 'string') {
    throw new HttpError(400, 'INVALID_INPUT', 'Email subject must be a string.');
  }

  if (emailBody !== undefined && typeof emailBody !== 'string') {
    throw new HttpError(400, 'INVALID_INPUT', 'Email body must be a string.');
  }

  const cleanSubject = typeof subject === 'string' ? subject.trim() : '';
  const cleanBody = typeof emailBody === 'string' ? emailBody.trim() : '';

  if (cleanSubject.length > 1000) {
    throw new HttpError(400, 'INVALID_INPUT', 'Email subject exceeds maximum length of 1000 characters.');
  }

  if (cleanBody.length > 50000) {
    throw new HttpError(400, 'INVALID_INPUT', 'Email body exceeds maximum length of 50000 characters.');
  }

  return {
    subject: cleanSubject,
    body: cleanBody,
  };
}

export function validateScanIdParam(params) {
  const id = params?.id;
  if (!id || typeof id !== 'string' || !UUID_REGEX.test(id)) {
    throw new HttpError(400, 'INVALID_INPUT', 'Invalid scan ID format. Must be a valid UUID.');
  }
  return id;
}

export function validateScanQuery(query) {
  let page = 1;
  let limit = 20;

  if (query?.page !== undefined) {
    page = parseInt(query.page, 10);
    if (Number.isNaN(page) || page < 1 || page > 1000000) {
      throw new HttpError(400, 'INVALID_INPUT', 'Page must be a positive integer not exceeding 1,000,000.');
    }
  }

  if (query?.limit !== undefined) {
    limit = parseInt(query.limit, 10);
    if (Number.isNaN(limit) || limit < 1 || limit > 100) {
      throw new HttpError(400, 'INVALID_INPUT', 'Limit must be an integer between 1 and 100.');
    }
  }

  let type;
  const inputType = query?.scanType !== undefined ? query.scanType : query?.type;
  if (inputType !== undefined && inputType !== '') {
    const rawType = String(inputType).toLowerCase();
    if (rawType !== 'url' && rawType !== 'email') {
      throw new HttpError(400, 'INVALID_INPUT', 'scanType must be either "url" or "email".');
    }
    type = rawType;
  }

  let classification;
  const inputVerdict = query?.verdict !== undefined ? query.verdict : query?.classification;
  if (inputVerdict !== undefined && inputVerdict !== '') {
    const rawClass = String(inputVerdict).toLowerCase();
    const validClasses = new Set(['benign', 'suspicious', 'phishing', 'safe', 'malicious']);
    if (!validClasses.has(rawClass)) {
      throw new HttpError(400, 'INVALID_INPUT', 'verdict must be SAFE, SUSPICIOUS, or PHISHING.');
    }
    if (rawClass === 'safe') classification = 'benign';
    else if (rawClass === 'malicious') classification = 'phishing';
    else classification = rawClass;
  }

  let sortBy = 'created_at';
  if (query?.sortBy !== undefined && query.sortBy !== '') {
    const allowedSort = new Set(['created_at', 'risk_score']);
    if (!allowedSort.has(query.sortBy)) {
      throw new HttpError(400, 'INVALID_INPUT', 'sortBy must be either "created_at" or "risk_score".');
    }
    sortBy = query.sortBy;
  }

  let sortOrder = 'DESC';
  if (query?.sortOrder !== undefined && query.sortOrder !== '') {
    const orderUpper = String(query.sortOrder).toUpperCase();
    if (orderUpper !== 'ASC' && orderUpper !== 'DESC') {
      throw new HttpError(400, 'INVALID_INPUT', 'sortOrder must be either "ASC" or "DESC".');
    }
    sortOrder = orderUpper;
  }

  let search;
  if (query?.search !== undefined && query.search !== '') {
    search = String(query.search).trim();
    if (search.length > 200) {
      throw new HttpError(400, 'INVALID_INPUT', 'search string exceeds maximum length of 200 characters.');
    }
  }

  let from, to;
  if (query?.from !== undefined && query.from !== '') {
    const d = new Date(query.from);
    if (Number.isNaN(d.getTime())) {
      throw new HttpError(400, 'INVALID_INPUT', 'Invalid "from" date format.');
    }
    from = d.toISOString();
  }
  
  if (query?.to !== undefined && query.to !== '') {
    const d = new Date(query.to);
    if (Number.isNaN(d.getTime())) {
      throw new HttpError(400, 'INVALID_INPUT', 'Invalid "to" date format.');
    }
    to = d.toISOString();
  }

  return { page, limit, type, classification, sortBy, sortOrder, search, from, to };
}

