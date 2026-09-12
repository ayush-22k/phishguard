import { env } from '../config/env.js';

export function notFoundHandler(_request, response) {
  response.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'The requested resource was not found.',
    },
  });
}

export function errorHandler(error, _request, response, _next) {
  const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : (Number.isInteger(error.status) ? error.status : 500);
  const isHttpError = error.constructor.name === 'HttpError' || error.statusCode !== undefined;
  const code = error.code || (statusCode < 500 ? 'BAD_REQUEST' : 'INTERNAL_ERROR');
  const message = isHttpError ? error.message : (statusCode < 500 ? error.message : 'An unexpected error occurred.');

  if (statusCode >= 500 && env.nodeEnv !== 'test') {
    console.error('Unhandled application error:', error);
  }

  response.status(statusCode).json({
    success: false,
    error: {
      code,
      message,
    },
  });
}
