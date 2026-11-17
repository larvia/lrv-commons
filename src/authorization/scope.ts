import { PermissionDeniedError } from './errors';
import { hasAnyPermission } from './permissions';
import { AccessTokenPayload, ModuleScope, PermissionKey } from './types';

/** Internal permission of the LarvIA staff that can work on any company. */
export const ACCESS_ANY_COMPANY_PERMISSION = 'companies:access-any';

/**
 * Internal permission of the sales staff to manage users, companies and balances of any company. Only the
 * users and balance services read it, so pass it in `anyCompanyPermissions` there; it does not open the
 * rest of the platform like `companies:access-any` does.
 */
export const MANAGE_ANY_COMPANY_PERMISSION = 'companies:manage-any';

/** A company id as the services hold it: a string, a Feathers `context.id` or a stored ObjectId. Compared as text. */
export type CompanyIdLike = string | number | { toString(): string };

export interface CompanyScopeOptions {
  /** Permissions that open any company; one is enough. Default: only `companies:access-any`. */
  anyCompanyPermissions?: readonly PermissionKey[];
  /**
   * Companies allowed besides the active one, resolved by the service (for example the companies assigned
   * to a partial admin or the clients of a distributor).
   */
  allowedCompanyIds?: ReadonlyArray<CompanyIdLike> | null;
}

/** Query filter of a list: one company, several (`$in`) or `{}` for any company. */
export interface CompanyListFilter {
  companyId?: string | { $in: string[] };
}

/** Claims the scope reads. Both are optional so the payload types of the services fit; without a company it is a 403. */
export type CompanyScopePayload = Partial<Pick<AccessTokenPayload, 'companyId' | 'permissions'>> | null | undefined;

const canAccessAnyCompany = (payload: CompanyScopePayload, options: CompanyScopeOptions) =>
  hasAnyPermission(payload?.permissions, options.anyCompanyPermissions ?? [ACCESS_ANY_COMPANY_PERMISSION]);

const toCompanyIds = (companyIds: CompanyScopeOptions['allowedCompanyIds']): string[] =>
  (companyIds || []).filter((companyId) => companyId !== undefined && companyId !== null).map(String).filter(Boolean);

/**
 * Company a request works on. It is the active company of the token unless the requester can access any
 * company or the company is in `allowedCompanyIds`. Asking for another company is rejected instead of
 * answered with the data of the active company, so a wrong `companyId` never goes unnoticed.
 */
export const resolveCompanyScope = (
  payload: CompanyScopePayload,
  requestedCompanyId?: CompanyIdLike | null,
  options: CompanyScopeOptions = {},
): string => {
  const activeCompanyId = payload?.companyId ? String(payload.companyId) : undefined;
  // Only a missing or empty id means the active company; a numeric 0 is an id too.
  const requested = requestedCompanyId === undefined || requestedCompanyId === null ? undefined : String(requestedCompanyId);

  if (!activeCompanyId) {
    throw new PermissionDeniedError('This action requires a company to scope to.');
  }

  if (!requested || requested === activeCompanyId) {
    return activeCompanyId;
  }

  if (canAccessAnyCompany(payload, options) || toCompanyIds(options.allowedCompanyIds).includes(requested)) {
    return requested;
  }

  throw new PermissionDeniedError('You cannot access data of another company.', { companyId: requested });
};

/**
 * Companies a list may show: the active one first, then `allowedCompanyIds`, without repeating them.
 * `undefined` when the requester can access any company: do not filter (like `resolveModuleFilter`).
 */
export const resolveCompanyIds = (payload: CompanyScopePayload, options: CompanyScopeOptions = {}): string[] | undefined => {
  if (canAccessAnyCompany(payload, options)) {
    return undefined;
  }

  const activeCompanyId = resolveCompanyScope(payload, undefined, options);
  return [...new Set([activeCompanyId, ...toCompanyIds(options.allowedCompanyIds)])];
};

/**
 * Query filter that keeps a list inside the active company, plus `allowedCompanyIds` (`$in`) when given;
 * `{}` when the requester can access any company.
 */
export function resolveCompanyFilter(
  payload: CompanyScopePayload,
  options?: CompanyScopeOptions & { allowedCompanyIds?: undefined },
): { companyId?: string };
export function resolveCompanyFilter(payload: CompanyScopePayload, options?: CompanyScopeOptions): CompanyListFilter;
export function resolveCompanyFilter(payload: CompanyScopePayload, options: CompanyScopeOptions = {}): CompanyListFilter {
  const companyIds = resolveCompanyIds(payload, options);

  if (!companyIds) {
    return {};
  }

  return companyIds.length === 1 ? { companyId: companyIds[0] } : { companyId: { $in: companyIds } };
}

/** Access to everything includes the modules created later, so it never lists them. */
export const canAccessModule = (scope: ModuleScope | null | undefined, moduleId: string): boolean => {
  if (!scope) {
    return false;
  }

  return scope.accessAll || scope.moduleIds.map(String).includes(String(moduleId));
};

/** Filter for a module field: `undefined` when the membership sees every module. */
export const resolveModuleFilter = (scope: ModuleScope | null | undefined): { $in: string[] } | undefined => {
  if (scope?.accessAll) {
    return undefined;
  }

  return { $in: (scope?.moduleIds || []).map(String) };
};
