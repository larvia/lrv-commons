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