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
