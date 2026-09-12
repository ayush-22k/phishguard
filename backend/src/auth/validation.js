import { HttpError } from '../utils/httpError.js';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    throw new HttpError(400, 'INVALID_INPUT', 'Invalid registration details.');
  }
}

export function validateRegistration(input) {
  const name = typeof input?.name === 'string' ? input.name.trim() : '';
  const email = normalizeEmail(input?.email);
  validatePassword(input?.password);

  if (name.length < 1 || name.length > 120 || !EMAIL_PATTERN.test(email) || email.length > 254) {
    throw new HttpError(400, 'INVALID_INPUT', 'Invalid registration details.');
  }

  return { name, email, password: input.password };
}

export function validateLogin(input) {
  const email = normalizeEmail(input?.email);
  if (!EMAIL_PATTERN.test(email) || email.length > 254 || typeof input?.password !== 'string' || input.password.length > 128) {
    throw new HttpError(400, 'INVALID_INPUT', 'Invalid login details.');
  }

  return { email, password: input.password };
}
