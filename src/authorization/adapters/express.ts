import { PermissionDeniedError } from '../errors';
import { hasAnyPermission, hasPermission, parsePermissionKey } from '../permissions';
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

const validateKeys = (middleware: string, keys: PermissionKey[]) => {
  if (!keys.length) {
    throw new Error(`${middleware}() needs at least one permission.`);
  }

  // Fails when the route is declared, not on the first request, if a key is misspelled.
  keys.forEach(parsePermissionKey);
};

const deny = (res: JsonResponse, data: Record<string, unknown>) => {
  const error = new PermissionDeniedError(undefined, data);
  return res.status(error.code).json(error.toJSON());
};

/**
 * Middleware that answers 403 unless the token grants every permission. Put it after the JWT middleware,
 * which leaves the payload in `req.authentication` (Feathers) or `req.user` (passport).
 */
export const requirePermissions = (...keys: PermissionKey[]) => {
  validateKeys('requirePermissions', keys);

  return (req: AuthorizableRequest, res: JsonResponse, next: () => void) => {
    const missing = keys.find((key) => !hasPermission(getPermissions(req), key));

    if (missing) {
      return deny(res, { permission: missing });
    }

    return next();
  };
};

/** Like `requirePermissions`, but one of the permissions is enough. */
export const requireAnyPermission = (...keys: PermissionKey[]) => {
  validateKeys('requireAnyPermission', keys);

  return (req: AuthorizableRequest, res: JsonResponse, next: () => void) => {
    if (!hasAnyPermission(getPermissions(req), keys)) {
      // A copy: changing the response must not change the keys of the route.
      return deny(res, { anyOf: [...keys] });
    }

    return next();
  };
};
