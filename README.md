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