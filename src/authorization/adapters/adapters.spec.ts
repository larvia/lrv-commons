import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';

import { PermissionDeniedError } from '../errors';

import { authorize, authorizeAny } from './feathers';
import { requirePermissions } from './express';
import { PermissionsGuard, REQUIRED_PERMISSIONS_KEY, RequirePermissions } from './nest';

const permissions = { stockings: 'find:create' };

describe('Feathers hooks', () => {
  const buildContext = (provider?: string): any => ({ params: { provider, authentication: { payload: { permissions } } } });

  it('lets an external call through when every permission is granted', () => {
    const context = buildContext('rest');

    expect(authorize('stockings:find', 'stockings:create')(context)).toBe(context);
  });

  it('rejects an external call that lacks a permission', () => {
    expect(() => authorize('stockings:delete')(buildContext('rest'))).toThrow(PermissionDeniedError);
  });

  it('trusts internal calls', () => {
    const context = buildContext(undefined);

    expect(authorize('stockings:delete')(context)).toBe(context);
  });

  it('accepts any of several permissions with authorizeAny', () => {
    expect(() => authorizeAny('stockings:delete', 'stockings:find')(buildContext('rest'))).not.toThrow();
  });

  it('fails when the hook is declared with a malformed key or without keys', () => {
    expect(() => authorize('stockings')).toThrow('Invalid permission key');
    expect(() => authorize()).toThrow('needs at least one permission');
  });
});

describe('Express middleware', () => {
  const buildResponse = () => {
    const res: any = { json: jest.fn() };
    res.status = jest.fn().mockReturnValue(res);
    return res;
  };

  it('calls next when the permission is granted', () => {
    const next = jest.fn();

    requirePermissions('stockings:create')({ authentication: { payload: { permissions } } }, buildResponse(), next);

    expect(next).toHaveBeenCalled();
  });

  it('answers 403 when the permission is missing', () => {
    const res = buildResponse();
    const next = jest.fn();

    requirePermissions('stockings:delete')({ user: { permissions } }, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 403, data: { permission: 'stockings:delete' } }));
    expect(next).not.toHaveBeenCalled();
  });
});

describe('Nest guard', () => {
  const buildContext = (request: any): any => ({
    getHandler: () => undefined,
    getClass: () => undefined,
    switchToHttp: () => ({ getRequest: () => request }),
  });
  const guardFor = (keys?: string[]) => new PermissionsGuard({ getAllAndOverride: () => keys } as any);

  it('stores the required permissions as metadata', () => {
    class StockingsController {
      @RequirePermissions('stockings:create')
      create() {
        return true;
      }
    }

    expect(Reflect.getMetadata(REQUIRED_PERMISSIONS_KEY, StockingsController.prototype.create)).toEqual(['stockings:create']);
  });

  it('allows a request whose token grants the permissions', () => {
    expect(guardFor(['stockings:create']).canActivate(buildContext({ user: { permissions } }))).toBe(true);
  });

  it('rejects a request whose token lacks a permission', () => {
    expect(() => guardFor(['stockings:delete']).canActivate(buildContext({ user: { permissions } }))).toThrow(ForbiddenException);
  });

  it('rejects endpoints that do not declare their permissions (deny by default)', () => {
    expect(() => guardFor(undefined).canActivate(buildContext({ user: { permissions } }))).toThrow(ForbiddenException);
  });
});
