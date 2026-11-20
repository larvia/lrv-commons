# lrv-commons

Shared code of the LARVIA services.

## Authorization

The access token carries the permissions of the user in the active company (`permissions` claim:
`{ model: "action:action" }`). Check them by key (`model:action`), never by role:

```ts
import { authorize, assertPermission, resolveCompanyScope } from 'lrv-commons';

// Feathers: before: { create: [authenticate('jwt'), authorize('stockings:create')] }
// Express:  app.post('/route', authenticate('jwt'), requirePermissions('stockings:create'), handler)
// Nest:     import { PermissionsGuard, RequirePermissions } from 'lrv-commons/dist/nest';
//           deny-by-default: an endpoint without @RequirePermissions is rejected.

const companyId = resolveCompanyScope(payload, query.companyId); // another company only with companies:access-any
```

Added in 1.2.0, all optional:

```ts
// Express, one of several permissions is enough:
app.get('/route', authenticate('jwt'), requireAnyPermission('historical-company-balances:find', 'payments:create'), handler);

// Other permissions that open any company, and companies the service resolved itself (no I/O here).
const options = { anyCompanyPermissions: [ACCESS_ANY_COMPANY_PERMISSION, MANAGE_ANY_COMPANY_PERMISSION], allowedCompanyIds };
resolveCompanyScope(payload, query.companyId, options);
resolveCompanyFilter(payload, options); // { companyId }, { companyId: { $in } } or {}
resolveCompanyIds(payload, options); // the same companies as a list, or undefined for any company (no filter)

// JWT strategy, after Feathers verified the signature:
classifyAccessToken({ header, payload }); // { kind: 'user' | 'integration' } or { kind: 'invalid', reason }
isTokenOutdated(payload, membership?.version); // true: throw new TokenRejectedError(TOKEN_OUTDATED_REASON), a 401
```

`STAFF_ROLE_KEYS` and `CLIENT_VISIBLE_ROLE_KEYS` are the role template lists of lrv-auth-service.

Added in 1.3.0: declared policies and deny-by-default. Feathers and Express stay out of the dependencies: each
service passes its own `authenticate('jwt')` and `JWTStrategy`.

```ts
// Every Feathers method declares its policy; an undeclared method answers 405, an unregistered service 403.
const policies = defineServicePolicies({
  payments: { find: policy.permissions({ all: ['payments:find'] }) },
  users: { get: policy.permissions({ all: ['users:get'] }, { self: { from: 'id' } }) }, // the own record needs no key
  'header-settings': {}, // closed to external calls
});
app.hooks({ before: { all: [createServicePolicyHook({ policies, authenticate: authentication.hooks.authenticate('jwt') })] } });

// Every Express route goes through secureRoute, so it cannot exist without a policy.
const { secureRoute } = createSecureRoute({ authenticate: authenticate('jwt'), getServiceSecret: () => process.env.AUTHENTICATION_SECRET_SERVICE });
secureRoute(app, 'post', '/payments/upload', policy.permissions({ all: ['payments:upload'] }), uploadPayments);
secureRoute(app, 'get', '/users/:userId/balance', policy.self({ from: 'param', param: 'userId' }, { serviceSecret: true }), getBalance);
listRoutePolicies(app, Object.keys(app.services)); // coverage test: a route without policy skipped secureRoute (the
// /<path> and /<path>/:__feathersId routes of each service are left out; pass any id-less custom method route too)

// The 'jwt' strategy with the token checks: 'log' (default) only logs, 'enforce' answers 401.
const AccessTokenStrategy = withAccessTokenChecks(JWTStrategy, { mode: parseTokenCheckMode(process.env.ACCESS_TOKEN_CHECK_MODE), logger });
authentication.register('jwt', new AccessTokenStrategy());
```

Policies: `public(reason)`, `authenticated()`, `self(target)`, `permissions({ all | any }, { self })`, `apiKey()`
and `serviceSecret()`. A Feathers `self` reads `id` (get, update, patch, remove), a `query` or a `data` field; an
Express one, a route `param` the path declares, or the `token` (a token without `sub` is never self). Only Express
routes accept the service secret. `defineServicePolicies` and `secureRoute` throw at boot for a rule they cannot apply.
`isServiceSecret` compares in constant time.

The errors of this package have the shape of Feathers errors (`type: 'FeathersError'`), but they are not
`instanceof FeathersError`. Feathers answers them with the right status. A middleware that tells handled errors
apart, such as a Rollbar middleware that skips Feathers errors, must use `isFeathersLikeError(err)`; otherwise it
reports every 401, 403 and 405 of the policies, with the token of the request.

1.4.0 removes the retired `roles.TECHNICAL_SUPPORT`: `getHigherRole` ignores it in an old token, and it is no
longer in `STAFF_ROLE_KEYS`.

Install it pinned to a tag or commit, not to the default branch.

# README #

This README would normally document whatever steps are necessary to get your application up and running.

### What is this repository for? ###

* Quick summary
* Version
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)

### How do I get set up? ###

* Summary of set up
* Configuration
* Dependencies
* Database configuration
* How to run tests
* Deployment instructions

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact