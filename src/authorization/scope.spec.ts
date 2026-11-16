import { PermissionDeniedError } from './errors';
import { canAccessModule, resolveCompanyFilter, resolveCompanyScope, resolveModuleFilter } from './scope';

const client = { companyId: 'company-1', permissions: { stockings: 'find' } };
const larviaStaff = { companyId: 'larvia', permissions: { companies: 'find:get:access-any' } };

describe('resolveCompanyScope', () => {
  it('uses the active company when no other company is requested', () => {
    expect(resolveCompanyScope(client)).toBe('company-1');
    expect(resolveCompanyScope(client, 'company-1')).toBe('company-1');
  });

  it('rejects another company without companies:access-any', () => {
    expect(() => resolveCompanyScope(client, 'company-2')).toThrow(PermissionDeniedError);
  });

  it('lets the LarvIA staff with companies:access-any work on any company', () => {
    expect(resolveCompanyScope(larviaStaff, 'company-2')).toBe('company-2');
    expect(resolveCompanyScope(larviaStaff)).toBe('larvia');
  });

  it('rejects a token without company', () => {
    expect(() => resolveCompanyScope({ companyId: '', permissions: {} })).toThrow('This action requires a company to scope to.');
    expect(() => resolveCompanyScope(undefined)).toThrow(PermissionDeniedError);
  });
});

describe('resolveCompanyFilter', () => {
  it('keeps lists inside the active company', () => {
    expect(resolveCompanyFilter(client)).toEqual({ companyId: 'company-1' });
  });

  it('does not filter for the staff that can access any company', () => {
    expect(resolveCompanyFilter(larviaStaff)).toEqual({});
  });
});

describe('module scope', () => {
  it('gives access to every module, including future ones, with access to everything', () => {
    const scope = { accessAll: true, moduleIds: [] };

    expect(canAccessModule(scope, 'module-created-later')).toBe(true);
    expect(resolveModuleFilter(scope)).toBeUndefined();
  });

  it('limits access to the listed modules otherwise', () => {
    const scope = { accessAll: false, moduleIds: ['module-1'] };

    expect(canAccessModule(scope, 'module-1')).toBe(true);
    expect(canAccessModule(scope, 'module-2')).toBe(false);
    expect(resolveModuleFilter(scope)).toEqual({ $in: ['module-1'] });
  });

  it('denies every module without a scope', () => {
    expect(canAccessModule(undefined, 'module-1')).toBe(false);
    expect(resolveModuleFilter(undefined)).toEqual({ $in: [] });
  });
});
