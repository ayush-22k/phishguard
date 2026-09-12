import assert from 'node:assert/strict';
import test from 'node:test';
import app from '../src/app.js';
import { validateScanQuery } from '../src/validators/scanValidators.js';

test('Security Audit - Trust Proxy is configured for Rate Limiter', () => {
  // express app.get('trust proxy') should be 1
  assert.equal(app.get('trust proxy'), 1, 'Trust proxy must be set for express-rate-limit to work securely behind a reverse proxy.');
});

test('Security Audit - Pagination page parameter is bounded to prevent DB offset overflow', () => {
  // A giant page number should throw HttpError
  try {
    validateScanQuery({ page: '99999999999999999999999' });
    assert.fail('Should have thrown an error for oversized page parameter');
  } catch (err) {
    assert.equal(err.statusCode || err.status, 400);
    assert.ok(err.message.includes('not exceeding'), 'Error message should mention the max limit');
  }
});

