import { PermissionDeniedError } from './errors';
import { hasPermission } from './permissions';
import { AccessTokenPayload, ModuleScope } from './types';

/** Internal permission of the LarvIA staff that can work on any company. */
export const ACCESS_ANY_COMPANY_PERMISSION = 'companies:access-any';

type CompanyScopePayload = Pick<AccessTokenPayload, 'companyId' | 'permissions'> | null | undefined;

const canAccessAnyCompany = (payload: CompanyScopePayload) => hasPermission(payload?.permissions, ACCESS_ANY_COMPANY_PERMISSION);

/**
 * Company a request works on. It is the active company of the token unless the requester can access any
 * company. Asking for another company without that permission is rejected instead of answered with the
 * data of the active company, so a wrong `companyId` never goes unnoticed.
 */
export const resolveCompanyScope = (payload: CompanyScopePayload, requestedCompanyId?: string | null): string => {
  const activeCompanyId = payload?.companyId ? String(payload.companyId) : undefined;
  const requested = requestedCompanyId ? String(requestedCompanyId) : undefined;

  if (!activeCompanyId) {
    throw new PermissionDeniedError('This action requires a company to scope to.');
  }

  if (!requested || requested === activeCompanyId) {
    return activeCompanyId;
  }

  if (canAccessAnyCompany(payload)) {
    return requested;
  }

  throw new PermissionDeniedError('You cannot access data of another company.', { companyId: requested });
};

/** Query filter that keeps a list inside the active company; `{}` when the requester can access any company. */
export const resolveCompanyFilter = (payload: CompanyScopePayload): { companyId?: string } => {
  if (canAccessAnyCompany(payload)) {
    return {};
  }

  return { companyId: resolveCompanyScope(payload) };
};

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
