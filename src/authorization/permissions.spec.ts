import { PermissionDeniedError } from './errors';
import {
  assertAnyPermission, assertPermission, assertPermissions, getGrantedActions, hasAllPermissions, hasAnyPermission,
  hasPermission, parsePermissionKey, toPermissionKey,
} from './permissions';

const permissions = { stockings: 'find:get:create:download-report', Analysis: 'FIND' };

describe('permission keys', () => {
  it('builds and splits model:action keys', () => {
    expect(toPermissionKey('stockings', 'download-report')).toBe('stockings:download-report');
    expect(parsePermissionKey('stockings:download-report')).toEqual({ modelName: 'stockings', action: 'download-report' });
  });

  it.each(['stockings', ':create', 'stockings:', ''])('rejects the malformed key "%s"', (key) => {
    expect(() => parsePermissionKey(key)).toThrow('Invalid permission key');
  });
});

describe('hasPermission', () => {
  it('grants the actions listed for the model', () => {
    expect(hasPermission(permissions, 'stockings:create')).toBe(true);
    expect(hasPermission(permissions, 'stockings:download-report')).toBe(true);
  });

  it('denies an action that is not listed', () => {
    expect(hasPermission(permissions, 'stockings:delete')).toBe(false);
  });

  it('denies a model that is not listed and a missing claim', () => {
    expect(hasPermission(permissions, 'harvests:find')).toBe(false);
    expect(hasPermission(undefined, 'stockings:find')).toBe(false);
    expect(hasPermission(null, 'stockings:find')).toBe(false);
  });

  it('compares model names and actions without case (the old helpers crashed on this)', () => {
    expect(hasPermission(permissions, 'ANALYSIS:find')).toBe(true);
    expect(getGrantedActions(permissions, 'analysis')).toEqual(['find']);
  });

  it('does not match an action that is only a prefix of a granted one', () => {
    expect(hasPermission({ stockings: 'download-report' }, 'stockings:download')).toBe(false);
  });

  it('checks any or all of several keys', () => {
    expect(hasAnyPermission(permissions, ['stockings:delete', 'stockings:get'])).toBe(true);
    expect(hasAllPermissions(permissions, ['stockings:find', 'stockings:delete'])).toBe(false);
  });
});

describe('assertions', () => {
  it('throws a 403 error with the shape of a Feathers error', () => {
    expect.assertions(4);

    try {
      assertPermission(permissions, 'stockings:delete');
    } catch (error) {
      expect(error).toBeInstanceOf(PermissionDeniedError);
      expect((error as PermissionDeniedError).code).toBe(403);
      expect((error as PermissionDeniedError).type).toBe('FeathersError');
      expect((error as PermissionDeniedError).data).toEqual({ permission: 'stockings:delete' });
    }
  });

  it('passes when every key is granted', () => {
    expect(() => assertPermissions(permissions, ['stockings:find', 'stockings:get'])).not.toThrow();
  });

  it('passes when at least one key is granted', () => {
    expect(() => assertAnyPermission(permissions, ['stockings:delete', 'stockings:find'])).not.toThrow();
    expect(() => assertAnyPermission(permissions, ['stockings:delete', 'harvests:find'])).toThrow(PermissionDeniedError);
  });
});
