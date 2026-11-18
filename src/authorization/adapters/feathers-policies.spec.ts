import { defineServicePolicies, policy } from '../policies';
import { MethodNotAllowedError, PermissionDeniedError } from '../errors';

import { createServicePolicyHook } from './feathers-policies';

const authenticate = jest.fn(async (context: unknown) => context);

const policies = defineServicePolicies({
  closed: {},
  users: {
    find: policy.permissions({ all: ['users:find'] }),
    get: policy.permissions({ all: ['users:get'] }, { self: { from: 'id' } }),
  },
  catalog: {
    find: policy.public('catalog of plans'),
    create: policy.authenticated({ legacyRoleGuard: 'authorizeAdmin' }),
  },
  balances: {
    patch: policy.permissions({ any: ['client-balances:update', 'company-balances:update'] }),
  },
  reports: {
    find: policy.permissions({ all: ['reports:find'] }, { self: { from: 'query', field: 'userId' } }),
    create: policy.permissions({ all: ['reports:create'] }, { self: { from: 'data', field: 'userId' } }),
  },
  conversations: {
    find: policy.self({ from: 'query', field: 'conversationId', requirePresent: false }),
    create: policy.self({ from: 'data', field: 'conversationId' }),
  },
});

const enforce = createServicePolicyHook({ policies, authenticate });

const buildContext = (props: { path: string; method: string; id?: unknown; data?: unknown; query?: unknown; provider?: string | null; payload?: unknown }): any => ({
  path: props.path,
  method: props.method,
  id: props.id,
  data: props.data,
  params: {
    provider: props.provider === null ? undefined : props.provider ?? 'rest',
    query: props.query,
    authentication: props.payload ? { strategy: 'jwt', accessToken: 'token', payload: props.payload } : undefined,
  },
});

const user = (permissions: Record<string, string> = {}) => ({ sub: '5001', roles: ['FINANCE'], permissions });

beforeEach(() => {
  authenticate.mockClear();
});

describe('createServicePolicyHook', () => {
  it('lets an internal call through without authenticating', async () => {
    const context = buildContext({ path: 'unknown', method: 'remove', provider: null });

    await expect(enforce(context)).resolves.toBe(context);
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('answers 403 for a service that is not registered', async () => {
    await expect(enforce(buildContext({ path: 'unknown', method: 'find' }))).rejects.toBeInstanceOf(PermissionDeniedError);
    await expect(enforce(buildContext({ path: 'unknown', method: 'find' })))
      .rejects.toMatchObject({ code: 403, className: 'forbidden', data: { reason: 'unregisteredService' } });
  });

  it.each([
    ['users', 'patch'],
    ['users', 'remove'],
    ['closed', 'find'],
  ])('answers 405 for %s.%s, which is not declared, before authenticating', async (path, method) => {
    const call = enforce(buildContext({ path, method, payload: user() }));

    await expect(call).rejects.toBeInstanceOf(MethodNotAllowedError);
    await expect(enforce(buildContext({ path, method, payload: user() })))
      .rejects.toMatchObject({ code: 405, className: 'method-not-allowed', message: `Method \`${method}\` is not supported by this endpoint.`, data: { reason: 'undeclaredMethod' } });
    expect(authenticate).not.toHaveBeenCalled();
  });

  it.each([['constructor', 'find'], ['users', 'constructor'], ['users', '__proto__'], ['users', 'hasOwnProperty']])(
    'never finds an inherited value for %s.%s',
    async (path, method) => {
      await expect(enforce(buildContext({ path, method, payload: user() }))).rejects.toMatchObject({ code: path === 'users' ? 405 : 403 });
    },
  );

  it('propagates the error of the authentication', async () => {
    authenticate.mockRejectedValueOnce(Object.assign(new Error('Not authenticated'), { code: 401 }));

    await expect(enforce(buildContext({ path: 'users', method: 'find' }))).rejects.toMatchObject({ code: 401 });
  });

  it('answers 401 when the given authenticate leaves no payload, whatever it returned', async () => {
    const lenient = createServicePolicyHook({ policies, authenticate: () => undefined });

    await expect(lenient(buildContext({ path: 'catalog', method: 'create' }))).rejects.toMatchObject({ code: 401, className: 'not-authenticated' });
    await expect(lenient(buildContext({ path: 'users', method: 'get', id: 'undefined' }))).rejects.toMatchObject({ code: 401 });
  });

  describe('a registry built without defineServicePolicies', () => {
    // A plain object passes the type; the hook still has to fail closed on what the boot check would refuse.
    const raw = createServicePolicyHook({
      policies: {
        reports: { find: { kind: 'permissions', all: ['reports:find'], self: { from: 'query', field: 'userId', requirePresent: false } } },
        secrets: { find: { kind: 'serviceSecret' } as never },
        keys: { find: { kind: 'apiKey' } as never },
        empty: { find: { kind: 'permissions' } as never },
      },
      authenticate,
    });

    it('asks for the permission when the self field of a permission is missing, even with requirePresent false', async () => {
      await expect(raw(buildContext({ path: 'reports', method: 'find', query: {}, payload: user() }))).rejects.toMatchObject({ code: 403, data: { permission: 'reports:find' } });
      await expect(raw(buildContext({ path: 'reports', method: 'find', query: { $or: [{ userId: '6002' }] }, payload: user() }))).rejects.toMatchObject({ code: 403 });
    });

    it.each(['secrets', 'keys', 'empty'])('never lets %s through: an unknown policy or a permission without keys', async (path) => {
      await expect(raw(buildContext({ path, method: 'find', payload: user({ users: 'find' }) }))).rejects.toMatchObject({ code: 403, data: { reason: 'unsupportedPolicy' } });
    });
  });

  it('lets a public method through without authenticating', async () => {
    const result = await enforce(buildContext({ path: 'catalog', method: 'find' }));

    expect(result.params.authorizedBy).toBe('public');
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('only authenticates an authenticated method', async () => {
    const result = await enforce(buildContext({ path: 'catalog', method: 'create', payload: user() }));

    expect(authenticate).toHaveBeenCalledTimes(1);
    expect(result.params.authorizedBy).toBe('authenticated');
  });

  describe('a permission with the self exception', () => {
    it('lets a user read their own record without the permission', async () => {
      const result = await enforce(buildContext({ path: 'users', method: 'get', id: '5001', payload: user() }));
      expect(result.params.authorizedBy).toBe('self');
    });

    it('answers 403 with the missing key on another user', async () => {
      await expect(enforce(buildContext({ path: 'users', method: 'get', id: '6002', payload: user() })))
        .rejects.toMatchObject({ code: 403, data: { permission: 'users:get' } });
    });

    it('lets another user through with the permission', async () => {
      const result = await enforce(buildContext({ path: 'users', method: 'get', id: '6002', payload: user({ users: 'get' }) }));
      expect(result.params.authorizedBy).toBe('permission');
    });

    it('never treats a token without sub as self', async () => {
      await expect(enforce(buildContext({ path: 'users', method: 'get', id: 'undefined', payload: { companyId: 'c', permissions: {} } })))
        .rejects.toMatchObject({ code: 403 });
    });
  });

  it('accepts any of the keys of an any-of policy', async () => {
    await expect(enforce(buildContext({ path: 'balances', method: 'patch', payload: user({ 'company-balances': 'update' }) }))).resolves.toBeDefined();
    await expect(enforce(buildContext({ path: 'balances', method: 'patch', payload: user() })))
      .rejects.toMatchObject({ code: 403, data: { anyOf: ['client-balances:update', 'company-balances:update'] } });
  });

  it('answers 403 to a token without a permissions claim', async () => {
    await expect(enforce(buildContext({ path: 'users', method: 'find', payload: { sub: '5001', roles: ['X'] } })))
      .rejects.toMatchObject({ code: 403, message: 'You do not have the correct permissions.' });
  });

  it('does not share the result through params reused by internal calls', async () => {
    const context = buildContext({ path: 'users', method: 'get', id: '5001', payload: user() });
    const { params } = context;

    await enforce(context);

    expect(params.authorizedBy).toBeUndefined();
    expect(context.params.authorizedBy).toBe('self');
  });

  describe('the self exception of a permission on a query or data field', () => {
    it('lets the own record through without the permission', async () => {
      await expect(enforce(buildContext({ path: 'reports', method: 'find', query: { userId: '5001' }, payload: user() }))).resolves.toMatchObject({ params: { authorizedBy: 'self' } });
    });

    it('asks for the permission when the field is missing, hidden in an operator or sent as an array', async () => {
      const denied = { code: 403, data: { permission: 'reports:find' } };

      await expect(enforce(buildContext({ path: 'reports', method: 'find', query: {}, payload: user() }))).rejects.toMatchObject(denied);
      await expect(enforce(buildContext({ path: 'reports', method: 'find', query: { $or: [{ userId: '6002' }] }, payload: user() }))).rejects.toMatchObject(denied);
      await expect(enforce(buildContext({ path: 'reports', method: 'find', query: { userId: ['5001'] }, payload: user() }))).rejects.toMatchObject(denied);
    });

    it('asks for the permission on a multi create', async () => {
      await expect(enforce(buildContext({ path: 'reports', method: 'create', data: [{ userId: '5001' }], payload: user() })))
        .rejects.toMatchObject({ code: 403, data: { permission: 'reports:create' } });
    });
  });

  describe('a self rule on a query or data field', () => {
    it('accepts the own value and refuses another one or an operator', async () => {
      await expect(enforce(buildContext({ path: 'conversations', method: 'find', query: { conversationId: '5001' }, payload: user() }))).resolves.toBeDefined();
      await expect(enforce(buildContext({ path: 'conversations', method: 'create', data: { conversationId: '5001' }, payload: user() }))).resolves.toBeDefined();
      await expect(enforce(buildContext({ path: 'conversations', method: 'find', query: { conversationId: '6002' }, payload: user() })))
        .rejects.toMatchObject({ code: 403, message: 'User has not enough permissions for this action.' });
      await expect(enforce(buildContext({ path: 'conversations', method: 'find', query: { conversationId: { $ne: 'x' } }, payload: user() })))
        .rejects.toMatchObject({ code: 403 });
    });

    it('refuses a multi create even when the policy leaves a missing field to the service', async () => {
      const multi = createServicePolicyHook({
        policies: defineServicePolicies({ chat: { create: policy.self({ from: 'data', field: 'conversationId', requirePresent: false }) } }),
        authenticate,
      });

      await expect(multi(buildContext({ path: 'chat', method: 'create', data: [{ conversationId: '6002' }], payload: user() }))).rejects.toMatchObject({ code: 403 });
    });

    it('leaves a missing field to the service only when the policy says so', async () => {
      await expect(enforce(buildContext({ path: 'conversations', method: 'find', query: {}, payload: user() }))).resolves.toBeDefined();
      await expect(enforce(buildContext({ path: 'conversations', method: 'create', data: {}, payload: user() }))).rejects.toMatchObject({ code: 403 });
    });
  });
});
