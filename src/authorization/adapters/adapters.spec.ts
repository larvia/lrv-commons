import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';

import { PermissionDeniedError } from '../errors';

import { authorize, authorizeAny } from './feathers';
import { requireAnyPermission, requirePermissions } from './express';
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

  it('keeps the rule when the error of authorizeAny is changed', () => {
    const hook = authorizeAny('stockings:delete', 'harvests:find');

    try {
      hook(buildContext('rest'));
    } catch (error) {
      ((error as PermissionDeniedError).data?.anyOf as string[]).push('stockings:find');
    }

    expect(() => hook(buildContext('rest'))).toThrow(PermissionDeniedError);
  });

  describe('typed contexts, without any', () => {
    // `params.authentication` as @feathersjs/authentication 4 types it.
    interface FeathersContext {
      params: { provider?: string; authentication?: { strategy?: string; [key: string]: any } };
    }

    // A context of a service declared with interfaces, without index signatures.
    interface ServiceAuthentication {
      strategy: string;
      accessToken: string;
      payload: { companyId: string; permissions?: { [key: string]: any } };
    }

    interface ServiceContext {
      params: { provider?: string; authentication?: ServiceAuthentication };
    }

    const feathersContext: FeathersContext = { params: { provider: 'rest', authentication: { strategy: 'jwt', payload: { permissions } } } };
    const serviceContext: ServiceContext = {
      params: { provider: 'rest', authentication: { strategy: 'jwt', accessToken: 'token', payload: { companyId: 'company-1', permissions } } },
    };

    it('takes the context type of Feathers 4', () => {
      expect(authorize('stockings:find')(feathersContext)).toBe(feathersContext);
      expect(authorizeAny('stockings:delete', 'stockings:find')(feathersContext)).toBe(feathersContext);
      expect(() => authorize('stockings:delete')(feathersContext)).toThrow(PermissionDeniedError);
    });

    it('takes a context declared with interfaces', () => {
      expect(authorize('stockings:create')(serviceContext)).toBe(serviceContext);
      expect(authorizeAny('stockings:delete', 'stockings:create')(serviceContext)).toBe(serviceContext);
      expect(() => authorizeAny('stockings:delete')(serviceContext)).toThrow(PermissionDeniedError);
    });
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

  it('fails when the middleware is declared with a malformed key or without keys', () => {
    expect(() => requirePermissions('stockings')).toThrow('Invalid permission key');
    expect(() => requirePermissions()).toThrow('requirePermissions() needs at least one permission.');
  });

  describe('requireAnyPermission', () => {
    it('calls next when one of the permissions is granted', () => {
      const next = jest.fn();

      requireAnyPermission('stockings:delete', 'stockings:create')({ authentication: { payload: { permissions } } }, buildResponse(), next);

      expect(next).toHaveBeenCalled();
    });

    it('reads the permissions from req.user too', () => {
      const next = jest.fn();

      requireAnyPermission('harvests:find', 'stockings:find')({ user: { permissions } }, buildResponse(), next);

      expect(next).toHaveBeenCalled();
    });

    it('answers 403 with the accepted permissions when none is granted', () => {
      const res = buildResponse();
      const next = jest.fn();

      requireAnyPermission('stockings:delete', 'harvests:find')({ authentication: { payload: { permissions } } }, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        name: 'Forbidden',
        message: 'You do not have the correct permissions.',
        code: 403,
        className: 'forbidden',
        data: { anyOf: ['stockings:delete', 'harvests:find'] },
        errors: {},
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('answers 403 without a token payload', () => {
      const res = buildResponse();
      const next = jest.fn();

      requireAnyPermission('stockings:find')({}, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it('keeps the rule of the route when a 403 body is changed', () => {
      const middleware = requireAnyPermission('stockings:delete', 'harvests:find');
      const req = { authentication: { payload: { permissions } } };
      const res = buildResponse();
      const next = jest.fn();

      middleware(req, res, jest.fn());
      res.json.mock.calls[0][0].data.anyOf.push('stockings:find');
      middleware(req, buildResponse(), next);

      expect(next).not.toHaveBeenCalled();
    });

    it('fails when the middleware is declared with a malformed key or without keys', () => {
      expect(() => requireAnyPermission('stockings:find', 'stockings')).toThrow('Invalid permission key');
      expect(() => requireAnyPermission()).toThrow('requireAnyPermission() needs at least one permission.');
    });
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
