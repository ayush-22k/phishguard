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
  if (env.nodeEnv !== 'test') {
    console.error('Unhandled application error:', error);
  }

  response.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred.',
    },
  });
}
