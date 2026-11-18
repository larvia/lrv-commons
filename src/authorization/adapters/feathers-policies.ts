import { isSameUser } from '../self';
import { AccessTokenPayload } from '../types';
import { assertAnyPermission, assertPermissions } from '../permissions';
import { MethodNotAllowedError, NotAuthenticatedError, PermissionDeniedError } from '../errors';
import { MethodPolicy, SelfTarget, ServiceMethod, ServicePolicies } from '../policies';

/** The part of a Feathers hook context the policy hook reads and writes; Feathers is not a dependency. */
export interface PolicyHookContext {
  path: string;
  method: string;
  id?: unknown;
  data?: unknown;
  params: {
    provider?: string;
    query?: Record<string, unknown>;
    authentication?: { strategy?: string; accessToken?: string; payload?: Partial<AccessTokenPayload> };
    authorizedBy?: AuthorizedBy;
    // Feathers params carry more fields; they are kept as they are.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [key: string]: any;
  };
}

/** How the call was let through, left in `params.authorizedBy` for the handlers that still need it. */
export type AuthorizedBy = 'public' | 'authenticated' | 'self' | 'permission';

export interface ServicePolicyHookOptions {
  policies: ServicePolicies;
  /** The `authenticate('jwt')` hook of the service, so its registered strategy (with the token checks) applies. */
  authenticate: (context: never) => unknown;
}

const isMissing = (value: unknown) => value === undefined || value === null || value === '';

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

// A multi create (an array of data) has no single field to compare: it never counts as self, nor as missing.
const readTarget = (context: PolicyHookContext, target: SelfTarget): { value?: unknown; missing: boolean } => {
  switch (target.from) {
    case 'id':
      return { value: context.id, missing: false };
    case 'query':
    case 'data': {
      const source = target.from === 'query' ? context.params.query : context.data;

      if (!isPlainObject(source)) {
        return { value: undefined, missing: source === undefined || source === null };
      }

      const value = Object.prototype.hasOwnProperty.call(source, target.field) ? source[target.field] : undefined;
      return { value, missing: isMissing(value) };
    }
    default:
      // 'param' and 'token' only exist on Express routes; defineServicePolicies refuses them.
      return { value: undefined, missing: false };
  }
};

const isSelf = (context: PolicyHookContext, target: SelfTarget) =>
  isSameUser(readTarget(context, target).value, context.params.authentication?.payload?.sub);

// Only a self() policy leaves a missing field to the handler, which answers its own 400. As the exception of a
// permission, a missing field is not self, and the permission decides.
const leavesMissingFieldToHandler = (context: PolicyHookContext, target: SelfTarget) =>
  'requirePresent' in target && target.requirePresent === false && readTarget(context, target).missing;

// A copy, so internal calls that reuse the caller's params never see another call's result.
const authorizeAs = <T extends PolicyHookContext>(context: T, authorizedBy: AuthorizedBy): T => {
  context.params = { ...context.params, authorizedBy };
  return context;
};

/**
 * Deny-by-default for Feathers, as an app `before.all` hook: an external call to a service that is not registered
 * answers 403, to a method that is not declared 405, and every other call must pass its policy. Internal calls (no
 * provider) pass. `self` and `permissions` authenticate first with the given `authenticate('jwt')` hook.
 */
export const createServicePolicyHook = (options: ServicePolicyHookOptions) => {
  const { policies } = options;
  const authenticate = options.authenticate as (context: PolicyHookContext) => unknown;

  const enforce = async <T extends PolicyHookContext>(context: T, rule: MethodPolicy): Promise<T> => {
    if (rule.kind === 'public') {
      return authorizeAs(context, 'public');
    }

    await authenticate(context);

    if (!context.params.authentication?.payload) {
      // Whatever the given authenticate does, a rule that needs a user never passes without a verified payload.
      throw new NotAuthenticatedError('Not authenticated');
    }

    if (rule.kind === 'authenticated') {
      return authorizeAs(context, 'authenticated');
    }

    if (rule.kind === 'self') {
      if (!leavesMissingFieldToHandler(context, rule.target) && !isSelf(context, rule.target)) {
        throw new PermissionDeniedError('User has not enough permissions for this action.');
      }

      return authorizeAs(context, 'self');
    }

    if (rule.kind !== 'permissions' || (!rule.all?.length && !rule.any?.length)) {
      // A rule this guard does not know (or a permissions rule without keys) never lets the call through.
      throw new PermissionDeniedError('User has not enough permissions for this action.', { reason: 'unsupportedPolicy' });
    }

    if (rule.self && isSelf(context, rule.self)) {
      return authorizeAs(context, 'self');
    }

    const permissions = context.params.authentication?.payload?.permissions;

    if (rule.all) {
      assertPermissions(permissions, rule.all);
    }

    if (rule.any) {
      assertAnyPermission(permissions, rule.any);
    }

    return authorizeAs(context, 'permission');
  };

  return async <T extends PolicyHookContext>(context: T): Promise<T> => {
    if (!context.params.provider) {
      return context;
    }

    // Own properties only: a path or method such as 'constructor' must not find an inherited value.
    const entry = Object.prototype.hasOwnProperty.call(policies, context.path) ? policies[context.path] : undefined;

    if (!entry) {
      throw new PermissionDeniedError('This service is not available.', { reason: 'unregisteredService' });
    }

    const rule = Object.prototype.hasOwnProperty.call(entry, context.method) ? entry[context.method as ServiceMethod] : undefined;

    if (!rule) {
      throw new MethodNotAllowedError(`Method \`${context.method}\` is not supported by this endpoint.`, { reason: 'undeclaredMethod' });
    }

    return enforce(context, rule);
  };
};
