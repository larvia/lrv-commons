import { TokenRejectionReason } from './token';

/**
 * 403 error with the shape of a Feathers error (`type: 'FeathersError'`), so the Feathers error handler
 * answers 403 instead of turning it into a 500. Express handlers can use `code` and `toJSON()` directly.
 */
export class PermissionDeniedError extends Error {
  readonly type = 'FeathersError';
  readonly name = 'Forbidden';
  readonly code = 403;
  readonly className = 'forbidden';
  readonly errors = {};
  readonly data?: Record<string, unknown>;

  constructor(message = 'You do not have the correct permissions.', data?: Record<string, unknown>) {
    super(message);
    this.data = data;
    Object.setPrototypeOf(this, PermissionDeniedError.prototype);
  }

  toJSON() {
    return { name: this.name, message: this.message, code: this.code, className: this.className, data: this.data, errors: this.errors };
  }
}

/**
 * 401 for a rejected token, with the shape of a Feathers `NotAuthenticated` error and the reason in
 * `data.reason`, so every service answers it the same way and clients can tell `tokenOutdated` apart.
 */
export class TokenRejectedError extends Error {
  readonly type = 'FeathersError';
  readonly name = 'NotAuthenticated';
  readonly code = 401;
  readonly className = 'not-authenticated';
  readonly errors = {};
  readonly data: { reason: TokenRejectionReason };

  constructor(reason: TokenRejectionReason, message = 'The access token was rejected.') {
    super(message);
    this.data = { reason };
    Object.setPrototypeOf(this, TokenRejectedError.prototype);
  }

  toJSON() {
    return { name: this.name, message: this.message, code: this.code, className: this.className, data: this.data, errors: this.errors };
  }
}
