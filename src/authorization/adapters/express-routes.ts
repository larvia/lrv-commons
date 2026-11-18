import { isSameUser } from '../self';
import { isServiceSecret } from '../service-secret';
import { AccessTokenPayload } from '../types';
import { NotAuthenticatedError, PermissionDeniedError } from '../errors';
import { RoutePolicy, SelfTarget } from '../policies';
import { JsonResponse, requireAnyPermission, requirePermissions } from './express';

/** The policy of a route, kept on its first handler so a coverage test can read it from `app._router.stack`. */
export const ROUTE_POLICY = Symbol.for('lrv-commons.routePolicy');

export type RouteVerb = 'get' | 'post' | 'patch' | 'put' | 'delete';

/** The parts of an Express request the route guard reads and writes; Express is not a dependency. */
export interface GuardRequest {
  params: Record<string, string | undefined>;
  query: Record<string, unknown>;
  headers: Record<string, unknown>;
  authentication?: { strategy?: string; accessToken?: string; payload?: Partial<AccessTokenPayload> };
  principal?: 'service' | 'user';
}

type NextFunction = (err?: unknown) => void;

type Middleware = (req: never, res: never, next: NextFunction) => unknown;

type GuardMiddleware = (req: GuardRequest, res: JsonResponse, next: NextFunction) => unknown;

/** The part of an Express app `secureRoute` uses. */
export type RouteApp = { [verb in RouteVerb]: unknown };

export interface SecureRouteOptions {
  /** The `authenticate('jwt')` middleware of `@feathersjs/express`, so the registered strategy applies. */
  authenticate: Middleware;
  /** `process.env.AUTHENTICATION_SECRET_SERVICE`, read on each call so a test can change it. */
  getServiceSecret: () => string | undefined;
  /** Checks the legacy `?accessToken=` of a `serviceSecret({ queryAccessToken: true })` route; answers or calls next. */
  queryTokenHandler?: Middleware;
}

// Express routes have no Feathers id, query field or data field to compare: only these two targets work here.
const ROUTE_SELF_TARGETS: SelfTarget['from'][] = ['token', 'param'];

const routeSelfTarget = (routePolicy: RoutePolicy) => {
  if (routePolicy.kind === 'self') {
    return routePolicy.target;
  }

  return routePolicy.kind === 'permissions' ? routePolicy.self : undefined;
};

// The Feathers authenticate middleware always ends by calling next, with the error when it fails.
const runAuthenticate = (middleware: GuardMiddleware, req: GuardRequest, res: JsonResponse) => new Promise<void>((resolve, reject) => {
  middleware(req, res, (err?: unknown) => (err ? reject(err) : resolve()));
});

// The permission middlewares are synchronous: they call next or answer 403 themselves. A check that calls next with
// an error has not passed: the error goes to the guard's catch, never through to the handlers.
const passes = (check: GuardMiddleware, req: GuardRequest, res: JsonResponse) => {
  let passed = false;
  let failure: unknown;

  check(req, res, (err?: unknown) => {
    if (err) {
      failure = err;
      return;
    }
    passed = true;
  });

  if (failure) {
    throw failure;
  }

  return passed;
};

const acceptsServiceSecret = (routePolicy: RoutePolicy) =>
  routePolicy.kind === 'serviceSecret' || ('serviceSecret' in routePolicy && !!routePolicy.serviceSecret);

const forbidden = (res: JsonResponse) => {
  const error = new PermissionDeniedError('User has not enough permissions for this action.');
  return res.status(error.code).json(error.toJSON());
};

const unauthenticated = (res: JsonResponse, message: string) => {
  const error = new NotAuthenticatedError(message);
  return res.status(error.code).json(error.toJSON());
};

const buildPermissionChecks = (routePolicy: RoutePolicy): GuardMiddleware[] => {
  if (routePolicy.kind !== 'permissions') {
    return [];
  }

  return [
    ...(routePolicy.all ? [requirePermissions(...routePolicy.all) as GuardMiddleware] : []),
    ...(routePolicy.any ? [requireAnyPermission(...routePolicy.any) as GuardMiddleware] : []),
  ];
};

const isSelfRoute = (req: GuardRequest, target: SelfTarget) => {
  const sub = req.authentication?.payload?.sub;

  if (target.from === 'token') {
    // The caller's own account: a token without sub (an API key) has none.
    return isSameUser(sub, sub);
  }

  return target.from === 'param' && isSameUser(req.params[target.param], sub);
};

// Express 4 (path-to-regexp 0.1) reads `:name` anywhere in the path, with `name` as \w+: `:userId`, `:userId?`,
// `:userId(\w+)`, `:userId.json` and `:from-:userId` declare userId; `:userIds` does not.
const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const declaresParam = (path: string, param: string) => new RegExp(`:${escapeRegExp(param)}(?!\\w)`).test(path);

/**
 * Builds `secureRoute(app, verb, path, policy, ...handlers)` for a service. Every Express route of the service goes
 * through it, so a route cannot exist without a declared policy. The guard it adds first:
 * - accepts the service secret where the policy declares it, and marks `req.principal = 'service'`;
 * - lets `public` and `apiKey` routes through (an `apiKey` handler validates the key itself);
 * - otherwise authenticates the JWT (`req.principal = 'user'`) and applies `self` or the permissions.
 */
export const createSecureRoute = (options: SecureRouteOptions) => {
  const authenticate = options.authenticate as unknown as GuardMiddleware;
  const queryTokenHandler = options.queryTokenHandler as unknown as GuardMiddleware | undefined;

  const buildRouteGuard = (routePolicy: RoutePolicy) => {
    const permissionChecks = buildPermissionChecks(routePolicy);

    return async (req: GuardRequest, res: JsonResponse, next: NextFunction) => {
      try {
        if (acceptsServiceSecret(routePolicy) && isServiceSecret(req.authentication?.accessToken, options.getServiceSecret())) {
          req.principal = 'service';
          return next();
        }

        if (routePolicy.kind === 'public' || routePolicy.kind === 'apiKey') {
          return next();
        }

        if (routePolicy.kind === 'serviceSecret') {
          if (routePolicy.queryAccessToken && queryTokenHandler) {
            return await queryTokenHandler(req, res, next);
          }

          return unauthenticated(res, 'A valid service secret is required.');
        }

        await runAuthenticate(authenticate, req, res);
        req.principal = 'user';

        if (routePolicy.kind === 'authenticated') {
          return next();
        }

        if (routePolicy.kind === 'self') {
          return isSelfRoute(req, routePolicy.target) ? next() : forbidden(res);
        }

        if (routePolicy.kind !== 'permissions' || !permissionChecks.length) {
          // A policy this guard does not know (or a permissions rule without keys) never lets the call through.
          return forbidden(res);
        }

        if (routePolicy.self && isSelfRoute(req, routePolicy.self)) {
          return next();
        }

        // Each check answers 403 itself when it fails.
        return permissionChecks.every((check) => passes(check, req, res)) ? next() : undefined;
      } catch (err) {
        return next(err);
      }
    };
  };

  const secureRoute = (app: RouteApp, verb: RouteVerb, path: string, routePolicy: RoutePolicy, ...handlers: unknown[]) => {
    if (!handlers.length) {
      // app.get(path) with no handler is the settings getter, not a route.
      throw new Error(`secureRoute(${verb} ${path}) needs a handler.`);
    }

    const selfTarget = routeSelfTarget(routePolicy);
    if (selfTarget && !ROUTE_SELF_TARGETS.includes(selfTarget.from)) {
      // A self rule an Express route cannot check would answer 403 forever, or drop the exception of a permission.
      throw new Error(`secureRoute(${verb} ${path}) only takes self from token or param, not from ${selfTarget.from}.`);
    }

    if (selfTarget?.from === 'param' && !declaresParam(path, selfTarget.param)) {
      // A param the path does not declare is always undefined: the route would answer 403 to every caller.
      throw new Error(`secureRoute(${verb} ${path}) takes self from :${selfTarget.param}, which the path does not declare.`);
    }

    if (routePolicy.kind === 'serviceSecret' && routePolicy.queryAccessToken && !queryTokenHandler) {
      throw new Error(`secureRoute(${verb} ${path}) accepts a query token, but no queryTokenHandler was given.`);
    }

    const guard = buildRouteGuard(routePolicy);
    Object.defineProperty(guard, ROUTE_POLICY, { value: routePolicy });

    const register = app[verb] as (this: RouteApp, routePath: string, ...routeHandlers: unknown[]) => void;
    register.call(app, path, guard, ...handlers);
  };

  return { secureRoute, buildRouteGuard };
};

export interface RegisteredRoute {
  /** `VERB /path`, for example `GET /users/:id`. */
  key: string;
  policy?: RoutePolicy;
  /** Every handler of the route, the guard first. */
  handlers: unknown[];
}

interface RouterLayer {
  route?: { path: string; methods: Record<string, unknown>; stack: { handle: unknown }[] };
}

const trimSlashes = (path: string) => path.replace(/^\/+|\/+$/g, '');

/**
 * The Express routes of an app with the policy their guard carries, for a coverage test: a route without `policy`
 * was registered without `secureRoute`. Pass the Feathers service paths (`Object.keys(app.services)`): the routes
 * Feathers registers for them, `/<path>`, `/<path>/:__feathersId` and `/<path>/:__feathersId/<method>`, are left out.
 * A custom method without id (`/<path>/<method>`) is listed: pass its route path in `servicePaths` too, so a real
 * Express route such as `/<path>/search` is never hidden.
 */
export const listRoutePolicies = (app: { _router?: { stack: RouterLayer[] } }, servicePaths: Iterable<string> = []): RegisteredRoute[] => {
  const services = [...servicePaths].map((path) => `/${trimSlashes(path)}`);
  const isServiceRoute = (routePath: string) =>
    services.some((service) => routePath === service || routePath === `${service}/:__feathersId` || routePath.startsWith(`${service}/:__feathersId/`));

  return (app._router?.stack ?? [])
    .filter((layer) => layer.route && !isServiceRoute(layer.route.path))
    .flatMap((layer) => {
      const route = layer.route!;
      const handlers = route.stack.map((item) => item.handle);
      const policy = (handlers[0] as { [ROUTE_POLICY]?: RoutePolicy } | undefined)?.[ROUTE_POLICY];

      return Object.keys(route.methods)
        .filter((method) => route.methods[method])
        .map((method) => ({ key: `${method.toUpperCase()} ${route.path}`, policy, handlers }));
    });
};
