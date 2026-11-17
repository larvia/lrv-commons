import { assertAnyPermission, assertPermissions, parsePermissionKey } from '../permissions';
import { AccessTokenPayload, PermissionKey } from '../types';

/** The part of a Feathers hook context these hooks read; Feathers is not a dependency of this package. */
export interface AuthorizableHookContext {
  params: {
    provider?: string;
    authentication?: { payload?: Partial<AccessTokenPayload> };
  };
}

const validateKeys = (keys: PermissionKey[]) => {
  if (!keys.length) {
    throw new Error('authorize() needs at least one permission.');
  }

  // Fails when the service loads, not on the first request, if a key is misspelled.
  keys.forEach(parsePermissionKey);
};

/**
 * Hook that rejects the call with a 403 unless the token grants every permission. Internal calls (no
 * provider) are trusted, like `authenticate('jwt')` does. Run it after `authenticate('jwt')`:
 * `before: { create: [authenticate('jwt'), authorize('stockings:create')] }`.
 */
export const authorize = (...keys: PermissionKey[]) => {
  validateKeys(keys);

  return <T extends AuthorizableHookContext>(context: T): T => {
    if (context.params.provider) {
      assertPermissions(context.params.authentication?.payload?.permissions, keys);
    }

    return context;
  };
};

/** Like `authorize`, but one of the permissions is enough. */
export const authorizeAny = (...keys: PermissionKey[]) => {
  validateKeys(keys);

  return <T extends AuthorizableHookContext>(context: T): T => {
    if (context.params.provider) {
      assertAnyPermission(context.params.authentication?.payload?.permissions, keys);
    }

    return context;
  };
};
