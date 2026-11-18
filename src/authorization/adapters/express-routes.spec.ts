import { policy, RoutePolicy } from '../policies';

import * as express from './express';
import { createSecureRoute, listRoutePolicies, ROUTE_POLICY } from './express-routes';

const SECRET = 'service-secret';

let payload: Record<string, unknown> | undefined;
const authenticate = jest.fn((req: any, _res: any, next: (err?: unknown) => void) => {
  if (!payload) {
    return next(Object.assign(new Error('Not authenticated'), { code: 401 }));
  }

  req.authentication = { ...req.authentication, payload };
  return next();
});
const queryTokenHandler = jest.fn((_req: any, _res: any, next: () => void) => next());

const { secureRoute } = createSecureRoute({ authenticate, getServiceSecret: () => SECRET, queryTokenHandler });

const buildApp = () => {
  const routes: Record<string, any[]> = {};
  const record = (verb: string) => (path: string, ...handlers: any[]) => { routes[`${verb} ${path}`] = handlers; };

  return { routes, get: record('GET'), post: record('POST'), patch: record('PATCH'), put: record('PUT'), delete: record('DELETE') };
};

const buildRes = () => {
  const res: any = { status: jest.fn(), json: jest.fn() };
  res.status.mockReturnValue(res);
  return res;
};

// Registers one route and runs only its guard.
const runGuard = async (routePolicy: RoutePolicy, req: any, secure = secureRoute) => {
  const app = buildApp();
  secure(app, 'get', '/probe/:userId', routePolicy, jest.fn());

  const guard = app.routes['GET /probe/:userId'][0];
  const request = { params: {}, query: {}, headers: {}, ...req };
  const res = buildRes();
  const next = jest.fn();
  await guard(request, res, next);

  return { req: request, res, next };
};

beforeEach(() => {
  payload = { sub: '5001', permissions: { users: 'find' } };
  authenticate.mockClear();
  queryTokenHandler.mockClear();
});

describe('secureRoute', () => {
  it('registers the guard first, then the handlers in order, with the policy on the guard', () => {
    const app = buildApp();
    const first = jest.fn();
    const second = jest.fn();
    const routePolicy = policy.authenticated();

    secureRoute(app, 'post', '/things', routePolicy, first, second);

    const chain = app.routes['POST /things'];
    expect(chain).toHaveLength(3);
    expect(chain[0][ROUTE_POLICY]).toBe(routePolicy);
    expect(chain.slice(1)).toEqual([first, second]);
  });

  it('refuses a route without handlers', () => {
    expect(() => secureRoute(buildApp(), 'get', '/things', policy.authenticated())).toThrow('secureRoute(get /things) needs a handler.');
  });

  it.each([
    policy.self({ from: 'id' }),
    policy.self({ from: 'query', field: 'userId' }),
    policy.permissions({ all: ['users:get'] }, { self: { from: 'data', field: 'userId' } }),
  ])('refuses a self rule the route cannot check: %j', (routePolicy) => {
    expect(() => secureRoute(buildApp(), 'get', '/things', routePolicy, jest.fn())).toThrow('only takes self from token or param');
  });

  it.each([
    ['/users/:id/balance', policy.self({ from: 'param', param: 'userId' })],
    ['/users/:id', policy.permissions({ all: ['users:get'] }, { self: { from: 'param', param: 'userId' } })],
    ['/users/:userIds', policy.self({ from: 'param', param: 'userId' })],
    ['/users/:userIdx/balance', policy.self({ from: 'param', param: 'userId' })],
  ])('refuses a self param that %s does not declare', (path, routePolicy) => {
    expect(() => secureRoute(buildApp(), 'get', path, routePolicy, jest.fn())).toThrow('which the path does not declare');
  });

  it.each(['/users/:userId', '/users/:userId/balance', '/users/:userId?', '/users/:userId(\\w+)', '/users/:userId([^/]+)', '/users/:userId.json', '/pair/:from-:userId', '/files/:userId*'])('accepts a self param that %s declares', (path) => {
    expect(() => secureRoute(buildApp(), 'get', path, policy.self({ from: 'param', param: 'userId' }), jest.fn())).not.toThrow();
  });

  it('refuses a query token route when the service gave no handler for it', () => {
    const { secureRoute: withoutHandler } = createSecureRoute({ authenticate, getServiceSecret: () => SECRET });

    expect(() => withoutHandler(buildApp(), 'get', '/e2e', policy.serviceSecret({ queryAccessToken: true }), jest.fn()))
      .toThrow('no queryTokenHandler was given');
  });
});

describe('route guard', () => {
  describe('service secret', () => {
    it('accepts the secret where it is declared, without authenticating', async () => {
      const { req, next, res } = await runGuard(policy.authenticated({ serviceSecret: true }), { authentication: { accessToken: SECRET } });

      expect(next).toHaveBeenCalledWith();
      expect(req.principal).toBe('service');
      expect(res.status).not.toHaveBeenCalled();
      expect(authenticate).not.toHaveBeenCalled();
    });

    it('does not accept the secret where it is not declared', async () => {
      payload = undefined;
      const { next } = await runGuard(policy.authenticated(), { authentication: { accessToken: SECRET } });

      expect(authenticate).toHaveBeenCalledTimes(1);
      expect(next.mock.calls[0][0]).toMatchObject({ code: 401 });
    });

    it('falls back to the JWT when the secret does not match', async () => {
      const { req, next } = await runGuard(policy.authenticated({ serviceSecret: true }), { authentication: { accessToken: 'a-jwt' } });

      expect(authenticate).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      expect(req.principal).toBe('user');
    });

    it('answers 401 to a route that only takes the secret', async () => {
      const { res, next } = await runGuard(policy.serviceSecret(), { authentication: { accessToken: 'a-jwt' } });

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json.mock.calls[0][0]).toMatchObject({ name: 'NotAuthenticated', code: 401, message: 'A valid service secret is required.' });
    });

    it('hands a query token to the handler of the service', async () => {
      const { next } = await runGuard(policy.serviceSecret({ queryAccessToken: true }), { query: { accessToken: 'a-jwt' } });

      expect(queryTokenHandler).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      expect(authenticate).not.toHaveBeenCalled();
    });
  });

  it.each([policy.public('sign-up'), policy.apiKey()])('lets %j through without authenticating', async (routePolicy) => {
    const { next } = await runGuard(routePolicy, {});

    expect(next).toHaveBeenCalledWith();
    expect(authenticate).not.toHaveBeenCalled();
  });

  it.each([{ kind: 'unknown' }, { kind: 'permissions' }])('answers 403 to a policy the guard does not know: %j', async (routePolicy) => {
    const { next, res } = await runGuard(routePolicy as never, {});

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('passes an authentication error to next', async () => {
    payload = undefined;
    const { next } = await runGuard(policy.permissions({ all: ['users:find'] }), {});

    expect(next.mock.calls[0][0]).toMatchObject({ code: 401 });
  });

  describe('self', () => {
    const own = policy.self({ from: 'param', param: 'userId' });

    it('lets the caller work on their own account', async () => {
      const { next } = await runGuard(own, { params: { userId: '5001' } });
      expect(next).toHaveBeenCalledWith();
    });

    it('answers 403 for another account', async () => {
      const { next, res } = await runGuard(own, { params: { userId: '6002' } });

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json.mock.calls[0][0]).toMatchObject({ code: 403, message: 'User has not enough permissions for this action.' });
    });

    it('answers 403 to a token without sub', async () => {
      payload = { companyId: 'c' };
      const { res } = await runGuard(own, { params: { userId: 'undefined' } });

      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('only needs a user token for the token target', async () => {
      const { next } = await runGuard(policy.self({ from: 'token' }), {});
      expect(next).toHaveBeenCalledWith();
    });

    it.each([undefined, null, ''])('answers 403 to a token whose sub is %p on the token target', async (sub) => {
      payload = { companyId: 'c', sub };
      const { next, res } = await runGuard(policy.self({ from: 'token' }), {});

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('asks for the permission of a token without sub when self is the token', async () => {
      payload = { companyId: 'c', permissions: {} };
      const { next, res } = await runGuard(policy.permissions({ all: ['users:find'] }, { self: { from: 'token' } }), {});

      expect(next).not.toHaveBeenCalled();
      expect(res.json.mock.calls[0][0]).toMatchObject({ code: 403, data: { permission: 'users:find' } });
    });
  });

  describe('permissions', () => {
    it('answers 403 with the missing key', async () => {
      const { next, res } = await runGuard(policy.permissions({ all: ['users:update'] }), {});

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json.mock.calls[0][0]).toMatchObject({ code: 403, message: 'You do not have the correct permissions.', data: { permission: 'users:update' } });
    });

    it('answers 403 with the keys of an any-of rule', async () => {
      const { res } = await runGuard(policy.permissions({ any: ['users:update', 'users:create'] }), {});
      expect(res.json.mock.calls[0][0]).toMatchObject({ data: { anyOf: ['users:update', 'users:create'] } });
    });

    it('passes with the key', async () => {
      const { next } = await runGuard(policy.permissions({ all: ['users:find'] }), {});
      expect(next).toHaveBeenCalledWith();
    });

    it('lets the own account through without the key when self is declared', async () => {
      const { next } = await runGuard(policy.permissions({ all: ['users:update'] }, { self: { from: 'param', param: 'userId' } }), { params: { userId: '5001' } });
      expect(next).toHaveBeenCalledWith();
    });

    it('hands the error of a check to next instead of letting the call through', async () => {
      const failure = new Error('check failed');
      const spy = jest.spyOn(express, 'requirePermissions').mockReturnValueOnce((_req, _res, next) => (next as (err?: unknown) => void)(failure));
      const { secureRoute: withFailingCheck } = createSecureRoute({ authenticate, getServiceSecret: () => SECRET });

      const { next, res } = await runGuard(policy.permissions({ all: ['users:find'] }), {}, withFailingCheck);

      spy.mockRestore();
      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith(failure);
      expect(res.status).not.toHaveBeenCalled();
    });
  });
});

describe('listRoutePolicies', () => {
  it('skips the routes Feathers registers for each service, given as in app.services', () => {
    const handler = jest.fn();
    const layer = (path: string, method: string) => ({ route: { path, methods: { [method]: true }, stack: [{ handle: handler }] } });
    const app = {
      _router: {
        stack: [
          layer('/payments', 'get'), layer('/payments/:__feathersId', 'patch'), layer('/payments/:__feathersId/approve', 'post'),
          layer('/historical/payments', 'get'), layer('/historical/payments/:__feathersId', 'get'),
          layer('/payments-report', 'get'), layer('/payments/upload', 'post'), layer('/payments/:__feathersIdX', 'get'),
          layer('/payments/stats', 'get'),
        ],
      },
    };

    expect(listRoutePolicies(app, ['payments', '/historical/payments/']).map((route) => route.key))
      .toEqual(['GET /payments-report', 'POST /payments/upload', 'GET /payments/:__feathersIdX', 'GET /payments/stats']);
    // An id-less custom method is skipped only when its route path is passed too.
    expect(listRoutePolicies(app, ['payments', 'historical/payments', 'payments/stats']).map((route) => route.key))
      .toEqual(['GET /payments-report', 'POST /payments/upload', 'GET /payments/:__feathersIdX']);
  });

  it('lists every route of the router with the policy of its guard, skipping the Feathers services', () => {
    const routePolicy = policy.authenticated();
    const guard = Object.defineProperty(jest.fn(), ROUTE_POLICY, { value: routePolicy });
    const handler = jest.fn();
    const app = {
      _router: {
        stack: [
          { name: 'query' },
          { route: { path: '/payments/upload', methods: { post: true }, stack: [{ handle: guard }, { handle: handler }] } },
          { route: { path: '/legacy', methods: { get: true }, stack: [{ handle: handler }] } },
          { route: { path: '/payments', methods: { get: true }, stack: [{ handle: handler }] } },
        ],
      },
    };

    expect(listRoutePolicies(app, ['/payments'])).toEqual([
      { key: 'POST /payments/upload', policy: routePolicy, handlers: [guard, handler] },
      { key: 'GET /legacy', policy: undefined, handlers: [handler] },
    ]);
  });
});
