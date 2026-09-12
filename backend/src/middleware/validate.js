import { HttpError } from '../utils/httpError.js';

export function validateRequest(schema) {
  return function (request, _response, next) {
    try {
      if (schema.body) {
        request.body = schema.body(request.body);
      }
      if (schema.query) {
        request.query = schema.query(request.query);
      }
      if (schema.params) {
        request.params = schema.params(request.params);
      }
      next();
    } catch (error) {
      if (error instanceof HttpError) {
        return next(error);
      }
      return next(new HttpError(400, 'INVALID_INPUT', error.message || 'Invalid request data.'));
    }
  };
}

