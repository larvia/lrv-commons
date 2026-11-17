import { PermissionDeniedError } from './errors';
import { PermissionKey, PermissionsMap } from './types';

const normalize = (value: string) => value.trim().toLowerCase();

export const toPermissionKey = (modelName: string, action: string): PermissionKey => `${modelName}:${action}`;

/** Splits `model:action` at the first `:`; model names never contain one, actions may contain dashes. */
export const parsePermissionKey = (key: PermissionKey) => {
  const separator = key.indexOf(':');

  if (separator <= 0 || separator === key.length - 1) {
    throw new Error(`Invalid permission key "${key}": expected "model:action".`);
  }

  return { modelName: key.slice(0, separator), action: key.slice(separator + 1) };
};

/** Actions granted on a model. Model names and actions are compared without case. */
export const getGrantedActions = (permissions: PermissionsMap | null | undefined, modelName: string): string[] => {
  if (!permissions) {
    return [];
  }

  const wanted = normalize(modelName);
  const model = Object.keys(permissions).find((name) => normalize(name) === wanted);

  if (!model || typeof permissions[model] !== 'string') {
    return [];
  }

  return permissions[model].split(':').map(normalize).filter(Boolean);
};

export const hasPermission = (permissions: PermissionsMap | null | undefined, key: PermissionKey): boolean => {
  const { modelName, action } = parsePermissionKey(key);
  return getGrantedActions(permissions, modelName).includes(normalize(action));
};

export const hasAnyPermission = (permissions: PermissionsMap | null | undefined, keys: readonly PermissionKey[]): boolean =>
  keys.some((key) => hasPermission(permissions, key));

export const hasAllPermissions = (permissions: PermissionsMap | null | undefined, keys: readonly PermissionKey[]): boolean =>
  keys.every((key) => hasPermission(permissions, key));

/** Throws a 403 unless every key is granted. */
export const assertPermissions = (permissions: PermissionsMap | null | undefined, keys: readonly PermissionKey[]) => {
  const missing = keys.find((key) => !hasPermission(permissions, key));

  if (missing) {
    throw new PermissionDeniedError(undefined, { permission: missing });
  }
};

export const assertPermission = (permissions: PermissionsMap | null | undefined, key: PermissionKey) =>
  assertPermissions(permissions, [key]);

/** Throws a 403 unless at least one key is granted. */
export const assertAnyPermission = (permissions: PermissionsMap | null | undefined, keys: readonly PermissionKey[]) => {
  if (!hasAnyPermission(permissions, keys)) {
    // A copy: changing the error must not change the keys a hook checks.
    throw new PermissionDeniedError(undefined, { anyOf: [...keys] });
  }
};
