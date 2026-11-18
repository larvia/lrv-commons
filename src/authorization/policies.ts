import { parsePermissionKey } from './permissions';
import { PermissionKey } from './types';

/*
  Declarative policies (LD-62, design 5.1): every external call of a service must match a declared policy, and what is
  not declared is rejected. Feathers methods use `createServicePolicyHook`, Express routes `createSecureRoute`.
*/

export type ServiceMethod = 'find' | 'get' | 'create' | 'update' | 'patch' | 'remove';

export const SERVICE_METHODS: readonly ServiceMethod[] = Object.freeze(['find', 'get', 'create', 'update', 'patch', 'remove'] as ServiceMethod[]);

/**
 * Where the id of the target user is. 'token' means the handler only works on the caller's own account and has no
 * target id. With `requirePresent: false` a missing field is left to the handler, which answers its own 400.
 * Feathers methods take 'id', 'query' and 'data'; Express routes take 'param' and 'token'.
 */
export type SelfTarget =
  | { from: 'id' }
  | { from: 'query'; field: string; requirePresent?: boolean }
  | { from: 'data'; field: string; requirePresent?: boolean }
  | { from: 'param'; param: string }
  | { from: 'token' };

// `legacyRoleGuard` names the role switch that still decides after the policy, until a permission replaces it.
interface LegacyGuard {
  legacyRoleGuard?: string;
}

// Only Express routes may accept the service secret; the Feathers guard never does.
interface AcceptsServiceSecret {
  serviceSecret?: boolean;
}

export interface PublicPolicy {
  kind: 'public';
  reason: string;
}

export interface AuthenticatedPolicy extends LegacyGuard, AcceptsServiceSecret {
  kind: 'authenticated';
}

export interface SelfPolicy extends LegacyGuard, AcceptsServiceSecret {
  kind: 'self';
  target: SelfTarget;
}

/** Every key in `all`, or one key of `any`. With `self`, the caller's own record passes without them. */
export interface PermissionsPolicy extends LegacyGuard, AcceptsServiceSecret {
  kind: 'permissions';
  all?: PermissionKey[];
  any?: PermissionKey[];
  self?: SelfTarget;
}

/** The handler validates the integration API key itself. */
export interface ApiKeyPolicy {
  kind: 'apiKey';
}

/** Only the service secret; `queryAccessToken` also accepts a legacy `?accessToken=` checked by the service. */
export interface ServiceSecretPolicy {
  kind: 'serviceSecret';
  queryAccessToken?: boolean;
}

export type MethodPolicy = PublicPolicy | AuthenticatedPolicy | SelfPolicy | PermissionsPolicy;

export type RoutePolicy = MethodPolicy | ApiKeyPolicy | ServiceSecretPolicy;

type Options = LegacyGuard & AcceptsServiceSecret;

const validateTarget = (target: SelfTarget) => {
  if (target.from === 'param' && !target.param) {
    throw new Error('self() with a route param needs the param name.');
  }

  if ((target.from === 'query' || target.from === 'data') && !target.field) {
    throw new Error(`self() from ${target.from} needs the field name.`);
  }

  return Object.freeze({ ...target }) as SelfTarget;
};

// Drops the options that are not set, so two equal policies compare equal in the tests.
const compact = <T extends object>(value: T): T =>
  Object.freeze(Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined))) as T;

/** Policy constructors. Keys are checked when the module loads, so a misspelled key fails at boot, not per request. */
export const policy = {
  public: (reason: string): PublicPolicy => {
    if (!reason) {
      throw new Error('public() needs the reason the route is public.');
    }

    return compact({ kind: 'public', reason });
  },

  apiKey: (): ApiKeyPolicy => compact({ kind: 'apiKey' }),

  serviceSecret: (options: { queryAccessToken?: boolean } = {}): ServiceSecretPolicy =>
    compact({ kind: 'serviceSecret', queryAccessToken: options.queryAccessToken || undefined }),

  authenticated: (options: Options = {}): AuthenticatedPolicy =>
    compact({ kind: 'authenticated', serviceSecret: options.serviceSecret || undefined, legacyRoleGuard: options.legacyRoleGuard }),

  self: (target: SelfTarget, options: Options = {}): SelfPolicy =>
    compact({ kind: 'self', target: validateTarget(target), serviceSecret: options.serviceSecret || undefined, legacyRoleGuard: options.legacyRoleGuard }),

  permissions: (keys: { all?: PermissionKey[]; any?: PermissionKey[] }, options: Options & { self?: SelfTarget } = {}): PermissionsPolicy => {
    const all = keys.all?.length ? Object.freeze([...keys.all]) as PermissionKey[] : undefined;
    const any = keys.any?.length ? Object.freeze([...keys.any]) as PermissionKey[] : undefined;

    if (!all && !any) {
      throw new Error('permissions() needs at least one permission.');
    }

    [...(all || []), ...(any || [])].forEach(parsePermissionKey);

    return compact({
      kind: 'permissions',
      all,
      any,
      self: options.self ? validateTarget(options.self) : undefined,
      serviceSecret: options.serviceSecret || undefined,
      legacyRoleGuard: options.legacyRoleGuard,
    });
  },
};

const describeTarget = (target: SelfTarget) => {
  switch (target.from) {
    case 'id':
    case 'token':
      return target.from;
    case 'param':
      return `param:${target.param}`;
    default:
      // `?`: a missing field is left to the handler.
      return `${target.from}:${target.field}${target.requirePresent === false ? '?' : ''}`;
  }
};

/** Short text of a policy, for the snapshot of the coverage test. */
export const describePolicy = (value: RoutePolicy): string => {
  const legacy = 'legacyRoleGuard' in value && value.legacyRoleGuard ? ` [legacy:${value.legacyRoleGuard}]` : '';
  const secret = 'serviceSecret' in value && value.serviceSecret ? '+secret' : '';

  switch (value.kind) {
    case 'public':
      return 'public';
    case 'apiKey':
      return 'apiKey';
    case 'serviceSecret':
      return value.queryAccessToken ? 'secret|queryToken' : 'secret';
    case 'authenticated':
      return `authenticated${secret}${legacy}`;
    case 'self':
      return `self(${describeTarget(value.target)})${secret}${legacy}`;
    case 'permissions': {
      const keys = [value.all?.join(','), value.any ? `any:${value.any.join(',')}` : undefined].filter(Boolean).join(';');
      const self = value.self ? `|self(${describeTarget(value.self)})` : '';
      return `permissions(${keys})${self}${secret}${legacy}`;
    }
  }
};

export type ServicePolicies = Readonly<Record<string, Readonly<Partial<Record<ServiceMethod, MethodPolicy>>>>>;

// A Feathers method has an id only in get, update, patch and remove; find and create never compare it.
const METHODS_WITH_ID: ServiceMethod[] = ['get', 'update', 'patch', 'remove'];
const SERVICE_SELF_TARGETS: SelfTarget['from'][] = ['id', 'query', 'data'];

const METHOD_POLICY_KINDS: MethodPolicy['kind'][] = ['public', 'authenticated', 'self', 'permissions'];

const validateMethodPolicy = (path: string, method: ServiceMethod, rule: MethodPolicy) => {
  const where = `${path}.${method}`;

  if (!METHOD_POLICY_KINDS.includes(rule.kind)) {
    // apiKey and serviceSecret are Express route policies: the Feathers guard has nothing to check them with.
    throw new Error(`${where} cannot use a ${String(rule.kind)} policy: only public, authenticated, self and permissions apply to a service method.`);
  }

  if ('serviceSecret' in rule && rule.serviceSecret) {
    // The Feathers guard never accepts the service secret: a route that needs it is an Express route (secureRoute).
    throw new Error(`${where} cannot accept the service secret: only Express routes do.`);
  }

  const target = rule.kind === 'self' ? rule.target : rule.kind === 'permissions' ? rule.self : undefined;

  if (!target) {
    return;
  }

  if (!SERVICE_SELF_TARGETS.includes(target.from)) {
    throw new Error(`${where} only takes self from id, query or data, not from ${target.from}.`);
  }

  if (target.from === 'id' && !METHODS_WITH_ID.includes(method)) {
    throw new Error(`${where} has no id: self from id never applies there.`);
  }

  if (rule.kind === 'permissions' && 'requirePresent' in target && target.requirePresent === false) {
    // Without the field the call would not be self, so the permission decides: there is nothing to leave out.
    throw new Error(`${where}: requirePresent: false only works on a self() policy, not on the self exception of permissions().`);
  }
};

/**
 * The policies of the Feathers services, by service path. A method that is not listed answers 405 to external calls;
 * a service that is not listed, 403. A service listed with `{}` is closed to external calls. Throws at boot for a
 * rule the Feathers guard cannot apply: the service secret, a self target from a route param or the token, or self
 * from id on find or create.
 */
export const defineServicePolicies = (entries: Record<string, Partial<Record<ServiceMethod, MethodPolicy>>>): ServicePolicies => {
  Object.entries(entries).forEach(([path, methods]) => {
    Object.entries(methods).forEach(([method, rule]) => {
      if (!SERVICE_METHODS.includes(method as ServiceMethod)) {
        throw new Error(`${path}.${method} is not a Feathers service method.`);
      }

      if (rule) {
        validateMethodPolicy(path, method as ServiceMethod, rule);
      }
    });
  });

  return Object.freeze(Object.fromEntries(Object.entries(entries).map(([path, methods]) => [path, Object.freeze({ ...methods })])));
};
