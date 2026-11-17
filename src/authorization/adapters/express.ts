import { PermissionDeniedError } from '../errors';
import { hasPermission, parsePermissionKey } from '../permissions';
import { AccessTokenPayload, PermissionKey, PermissionsMap } from '../types';

/** The parts of an Express request/response these middlewares use; Express is not a dependency. */
export interface AuthorizableRequest {
  authentication?: { payload?: Partial<AccessTokenPayload> };
  user?: { permissions?: PermissionsMap };
}

export interface JsonResponse {
  status(code: number): JsonResponse;
  json(body: unknown): unknown;
}

const getPermissions = (req: AuthorizableRequest) => req.authentication?.payload?.permissions ?? req.user?.permissions;

/**
 * Middleware that answers 403 unless the token grants every permission. Put it after the JWT middleware,
 * which leaves the payload in `req.authentication` (Feathers) or `req.user` (passport).
 */
export const requirePermissions = (...keys: PermissionKey[]) => {
  if (!keys.length) {
    throw new Error('requirePermissions() needs at least one permission.');
  }

  keys.forEach(parsePermissionKey);

  return (req: AuthorizableRequest, res: JsonResponse, next: () => void) => {
    const missing = keys.find((key) => !hasPermission(getPermissions(req), key));

    if (missing) {
      const error = new PermissionDeniedError(undefined, { permission: missing });
      return res.status(error.code).json(error.toJSON());
    }

    return next();
  };
};
