import { isSameUser } from './self';
import { isFeathersLikeError, MethodNotAllowedError, NotAuthenticatedError, PermissionDeniedError, TokenRejectedError } from './errors';
import { isServiceSecret } from './service-secret';
import { defineServicePolicies, describePolicy, policy } from './policies';

describe('policy constructors', () => {
  it('rejects a malformed permission key when the policy is declared', () => {
    expect(() => policy.permissions({ all: ['users'] })).toThrow('Invalid permission key "users": expected "model:action".');
    expect(() => policy.permissions({ any: ['users:get', ':get'] })).toThrow('Invalid permission key ":get"');
  });

  it('needs at least one permission', () => {
    expect(() => policy.permissions({})).toThrow('permissions() needs at least one permission.');
    expect(() => policy.permissions({ all: [], any: [] })).toThrow('permissions() needs at least one permission.');
  });

  it('needs the param or the field of a self target', () => {
    expect(() => policy.self({ from: 'param', param: '' })).toThrow('self() with a route param needs the param name.');
    expect(() => policy.self({ from: 'query', field: '' })).toThrow('self() from query needs the field name.');
  });

  it('needs the reason a route is public', () => {
    expect(() => policy.public('')).toThrow('public() needs the reason the route is public.');
  });

  it('builds frozen policies without unset options', () => {
    const built = policy.authenticated();

    expect(built).toEqual({ kind: 'authenticated' });
    expect(Object.isFrozen(built)).toBe(true);
  });

  it('keeps a copy of the keys', () => {
    const keys = ['payments:find'];
    const built = policy.permissions({ all: keys });
    keys.push('payments:upload');

    expect(built.all).toEqual(['payments:find']);
  });
});

describe('describePolicy', () => {
  it.each([
    [policy.public('sign-up'), 'public'],
    [policy.apiKey(), 'apiKey'],
    [policy.serviceSecret(), 'secret'],
    [policy.serviceSecret({ queryAccessToken: true }), 'secret|queryToken'],
    [policy.authenticated(), 'authenticated'],
    [policy.authenticated({ serviceSecret: true }), 'authenticated+secret'],
    [policy.authenticated({ legacyRoleGuard: 'validateUserRole' }), 'authenticated [legacy:validateUserRole]'],
    [policy.self({ from: 'param', param: 'userId' }), 'self(param:userId)'],
    [policy.self({ from: 'token' }), 'self(token)'],
    [policy.self({ from: 'query', field: 'conversationId' }), 'self(query:conversationId)'],
    [policy.permissions({ all: ['users:get'] }, { self: { from: 'id' } }), 'permissions(users:get)|self(id)'],
    [policy.permissions({ any: ['a:b', 'c:d'] }), 'permissions(any:a:b,c:d)'],
    [policy.permissions({ all: ['users:find'] }, { legacyRoleGuard: 'validateUserRole' }), 'permissions(users:find) [legacy:validateUserRole]'],
    [policy.permissions({ all: ['a:b'], any: ['c:d', 'e:f'] }), 'permissions(a:b;any:c:d,e:f)'],
    [policy.self({ from: 'query', field: 'conversationId', requirePresent: false }), 'self(query:conversationId?)'],
  ])('describes %j as %s', (value, text) => {
    expect(describePolicy(value)).toBe(text);
  });
});

describe('defineServicePolicies', () => {
  it('freezes the registry and each service', () => {
    const policies = defineServicePolicies({ payments: { find: policy.permissions({ all: ['payments:find'] }) }, closed: {} });

    expect(Object.isFrozen(policies)).toBe(true);
    expect(Object.isFrozen(policies.payments)).toBe(true);
    expect(policies.closed).toEqual({});
  });

  it.each([
    [{ find: policy.self({ from: 'token' }) }, 'x.find only takes self from id, query or data, not from token.'],
    [{ get: policy.permissions({ all: ['x:get'] }, { self: { from: 'param', param: 'userId' } }) }, 'x.get only takes self from id, query or data, not from param.'],
    [{ create: policy.permissions({ any: ['x:create'] }, { serviceSecret: true }) }, 'x.create cannot accept the service secret: only Express routes do.'],
    [{ find: policy.permissions({ all: ['x:find'] }, { self: { from: 'id' } }) }, 'x.find has no id: self from id never applies there.'],
    [{ create: policy.self({ from: 'id' }) }, 'x.create has no id: self from id never applies there.'],
    [{ find: policy.permissions({ all: ['x:find'] }, { self: { from: 'query', field: 'userId', requirePresent: false } }) }, 'requirePresent: false only works on a self() policy'],
    [{ constructor: policy.authenticated() }, 'x.constructor is not a Feathers service method.'],
    [{ find: policy.serviceSecret() }, 'x.find cannot use a serviceSecret policy'],
    [{ find: policy.apiKey() }, 'x.find cannot use a apiKey policy'],
  ])('refuses at boot a rule the Feathers guard cannot apply: %j', (methods, message) => {
    expect(() => defineServicePolicies({ x: methods as never })).toThrow(message);
  });

  it('accepts the self targets each method can compare', () => {
    expect(() => defineServicePolicies({
      users: {
        get: policy.permissions({ all: ['users:get'] }, { self: { from: 'id' } }),
        patch: policy.permissions({ all: ['users:update'] }, { self: { from: 'id' } }),
        find: policy.self({ from: 'query', field: 'conversationId', requirePresent: false }),
        create: policy.self({ from: 'data', field: 'conversationId' }),
      },
    })).not.toThrow();
  });
});

describe('isSameUser', () => {
  it('compares the ids as text, ObjectId hex in any case', () => {
    expect(isSameUser('5f8d0c0c0c0c0c0c0c0c0c0c', '5F8D0C0C0C0C0C0C0C0C0C0C')).toBe(true);
    expect(isSameUser({ toHexString: () => '5001', toString: () => '5001' }, '5001')).toBe(true);
    expect(isSameUser('5001', '6002')).toBe(false);
  });

  it('never matches without sub, without a target or with a query operator', () => {
    expect(isSameUser('undefined', undefined)).toBe(false);
    expect(isSameUser('', '')).toBe(false);
    expect(isSameUser(undefined, '5001')).toBe(false);
    expect(isSameUser({ $ne: 'x' }, '5001')).toBe(false);
    // qs parses ?userId[]=5001 to an array, which stringifies to '5001'.
    expect(isSameUser(['5001'], '5001')).toBe(false);
  });
});

describe('isServiceSecret', () => {
  it('matches only the configured secret', () => {
    expect(isServiceSecret('service-secret', 'service-secret')).toBe(true);
    expect(isServiceSecret('service-secreT', 'service-secret')).toBe(false);
    expect(isServiceSecret('service', 'service-secret')).toBe(false);
  });

  it('never matches without a configured secret or with a credential that is not text', () => {
    expect(isServiceSecret('', '')).toBe(false);
    expect(isServiceSecret('anything', undefined)).toBe(false);
    expect(isServiceSecret(['service-secret'], 'service-secret')).toBe(false);
  });
});

describe('isFeathersLikeError', () => {
  it('recognizes the errors of this package and the Feathers ones, which carry type FeathersError', () => {
    [new PermissionDeniedError(), new NotAuthenticatedError(), new MethodNotAllowedError('m'), new TokenRejectedError('expired')]
      .forEach((error) => expect(isFeathersLikeError(error)).toBe(true));
    expect(isFeathersLikeError(Object.assign(new Error('Forbidden'), { type: 'FeathersError' }))).toBe(true);
  });

  it('leaves out any other error', () => {
    expect(isFeathersLikeError(new Error('boom'))).toBe(false);
    expect(isFeathersLikeError(undefined)).toBe(false);
    expect(isFeathersLikeError('FeathersError')).toBe(false);
  });
});
