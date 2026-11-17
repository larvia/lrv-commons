import { PermissionDeniedError } from './errors';
import {
  ACCESS_ANY_COMPANY_PERMISSION, CompanyScopeOptions, MANAGE_ANY_COMPANY_PERMISSION, canAccessModule, resolveCompanyFilter,
  resolveCompanyIds, resolveCompanyScope, resolveModuleFilter,
} from './scope';
import { AccessTokenPayload } from './types';

const client = { companyId: 'company-1', permissions: { stockings: 'find' } };
const larviaStaff = { companyId: 'larvia', permissions: { companies: 'find:get:access-any' } };
const sales = { companyId: 'larvia', permissions: { companies: 'find:get:manage-any' } };
const partialAdmin = { companyId: 'company-1', permissions: { users: 'find:get' } };
const anyCompanyPermissions = [ACCESS_ANY_COMPANY_PERMISSION, MANAGE_ANY_COMPANY_PERMISSION];
const objectId = (id: string) => ({ toString: () => id });

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

  it('compares a Feathers id or a stored ObjectId as text', () => {
    expect(resolveCompanyScope(partialAdmin, objectId('company-2'), { allowedCompanyIds: ['company-2'] })).toBe('company-2');
    expect(resolveCompanyScope({ companyId: '7', permissions: {} }, 7)).toBe('7');
    expect(() => resolveCompanyScope(client, 2)).toThrow(PermissionDeniedError);
  });

  it('does not take a numeric 0 as no company', () => {
    expect(() => resolveCompanyScope(client, 0)).toThrow('You cannot access data of another company.');
  });
});

describe('payload types of the services', () => {
  // Like the Payload of the Feathers services: `permissions` is optional.
  interface ServicePayload {
    companyId: string;
    sub: string;
    roles: string[];
    permissions?: { [key: string]: any };
  }

  const servicePayload: ServicePayload = { companyId: 'company-1', sub: 'user-1', roles: [] };
  // What the adapters read from the request or the hook context.
  const adapterPayload: Partial<AccessTokenPayload> = { sub: 'user-1' };

  it('accepts them without casts', () => {
    expect(resolveCompanyScope(servicePayload)).toBe('company-1');
    expect(() => resolveCompanyScope(servicePayload, 'company-2')).toThrow(PermissionDeniedError);
    expect(resolveCompanyFilter(servicePayload)).toEqual({ companyId: 'company-1' });
    expect(resolveCompanyIds(servicePayload)).toEqual(['company-1']);
  });

  it('answers 403 when the payload has no company', () => {
    expect(() => resolveCompanyScope(adapterPayload)).toThrow('This action requires a company to scope to.');
    expect(() => resolveCompanyFilter(adapterPayload)).toThrow('This action requires a company to scope to.');
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

describe('scope permission names', () => {
  it('names the permissions every service checks', () => {
    expect(ACCESS_ANY_COMPANY_PERMISSION).toBe('companies:access-any');
    expect(MANAGE_ANY_COMPANY_PERMISSION).toBe('companies:manage-any');
  });
});

describe('default scope options', () => {
  it('answers like before when no options or empty options are given', () => {
    for (const options of [undefined, {}]) {
      expect(resolveCompanyScope(client, 'company-1', options)).toBe('company-1');
      expect(() => resolveCompanyScope(client, 'company-2', options)).toThrow('You cannot access data of another company.');
      expect(resolveCompanyScope(larviaStaff, 'company-2', options)).toBe('company-2');
      expect(resolveCompanyFilter(client, options)).toEqual({ companyId: 'company-1' });
      expect(resolveCompanyFilter(larviaStaff, options)).toEqual({});
    }
  });

  it('opens any company only with companies:access-any by default', () => {
    expect(() => resolveCompanyScope(sales, 'company-2')).toThrow(PermissionDeniedError);
    expect(resolveCompanyFilter(sales)).toEqual({ companyId: 'larvia' });
  });

  it('keeps the return type of the filter without allowedCompanyIds', () => {
    const filter: { companyId?: string } = resolveCompanyFilter(client, { anyCompanyPermissions });

    expect(filter).toEqual({ companyId: 'company-1' });
  });

  it('types the filter with allowedCompanyIds as one company or several', () => {
    const options: CompanyScopeOptions = { allowedCompanyIds: ['company-2'] };

    // @ts-expect-error with allowedCompanyIds the filter may be $in
    const filter: { companyId?: string } = resolveCompanyFilter(partialAdmin, { allowedCompanyIds: ['company-2'] });
    // @ts-expect-error same with a variable of the options type
    const fromOptions: { companyId?: string } = resolveCompanyFilter(partialAdmin, options);

    expect(filter).toEqual({ companyId: { $in: ['company-1', 'company-2'] } });
    expect(fromOptions).toEqual(filter);
  });
});

describe('anyCompanyPermissions', () => {
  it('opens any company with one of the listed permissions', () => {
    expect(resolveCompanyScope(sales, 'company-2', { anyCompanyPermissions })).toBe('company-2');
    expect(resolveCompanyScope(larviaStaff, 'company-2', { anyCompanyPermissions })).toBe('company-2');
    expect(resolveCompanyFilter(sales, { anyCompanyPermissions })).toEqual({});
  });

  it('replaces the default list', () => {
    const options = { anyCompanyPermissions: [MANAGE_ANY_COMPANY_PERMISSION] };

    expect(() => resolveCompanyScope(larviaStaff, 'company-2', options)).toThrow(PermissionDeniedError);
    expect(resolveCompanyFilter(larviaStaff, options)).toEqual({ companyId: 'larvia' });
  });

  it('still keeps a client in its company', () => {
    expect(() => resolveCompanyScope(client, 'company-2', { anyCompanyPermissions })).toThrow(PermissionDeniedError);
    expect(resolveCompanyFilter(client, { anyCompanyPermissions })).toEqual({ companyId: 'company-1' });
  });

  it('accepts a read-only list, like the frozen lists of this package', () => {
    const frozen = Object.freeze([ACCESS_ANY_COMPANY_PERMISSION, MANAGE_ANY_COMPANY_PERMISSION]);
    const asConst = [MANAGE_ANY_COMPANY_PERMISSION] as const;

    expect(resolveCompanyScope(sales, 'company-2', { anyCompanyPermissions: frozen })).toBe('company-2');
    expect(resolveCompanyFilter(sales, { anyCompanyPermissions: asConst })).toEqual({});
  });
});

describe('allowedCompanyIds', () => {
  const allowedCompanyIds = ['company-2', objectId('company-3')];

  it('lets the requester work on the allowed companies, given as strings or ids', () => {
    expect(resolveCompanyScope(partialAdmin, 'company-2', { allowedCompanyIds })).toBe('company-2');
    expect(resolveCompanyScope(partialAdmin, 'company-3', { allowedCompanyIds })).toBe('company-3');
    expect(resolveCompanyScope(partialAdmin, undefined, { allowedCompanyIds })).toBe('company-1');
  });

  it('rejects a company outside the list with the requested id', () => {
    expect.assertions(2);

    try {
      resolveCompanyScope(partialAdmin, 'company-4', { allowedCompanyIds });
    } catch (error) {
      expect(error).toBeInstanceOf(PermissionDeniedError);
      expect((error as PermissionDeniedError).data).toEqual({ companyId: 'company-4' });
    }
  });

  it('filters lists by the active company and the allowed ones, without repeating them', () => {
    expect(resolveCompanyFilter(partialAdmin, { allowedCompanyIds: [...allowedCompanyIds, 'company-1', 'company-2'] }))
      .toEqual({ companyId: { $in: ['company-1', 'company-2', 'company-3'] } });
  });

  it('answers like before when the list is empty, missing or only has the active company', () => {
    expect(resolveCompanyFilter(partialAdmin, { allowedCompanyIds: [] })).toEqual({ companyId: 'company-1' });
    expect(resolveCompanyFilter(partialAdmin, { allowedCompanyIds: null })).toEqual({ companyId: 'company-1' });
    expect(resolveCompanyFilter(partialAdmin, { allowedCompanyIds: ['company-1'] })).toEqual({ companyId: 'company-1' });
    expect(() => resolveCompanyScope(partialAdmin, 'company-2', { allowedCompanyIds: [] })).toThrow(PermissionDeniedError);
  });

  it('ignores empty ids in the list', () => {
    const withEmptyIds = ['', null, undefined, 'company-2'] as unknown as string[];

    expect(resolveCompanyFilter(partialAdmin, { allowedCompanyIds: withEmptyIds })).toEqual({ companyId: { $in: ['company-1', 'company-2'] } });
    expect(() => resolveCompanyScope(partialAdmin, 'null', { allowedCompanyIds: withEmptyIds })).toThrow(PermissionDeniedError);
  });

  it('does not filter when the requester can also access any company', () => {
    expect(resolveCompanyFilter(sales, { anyCompanyPermissions, allowedCompanyIds })).toEqual({});
  });
});

describe('resolveCompanyIds', () => {
  const allowedCompanyIds = ['company-2', objectId('company-3'), 'company-1', 'company-2'];

  it('lists the active company first and then the allowed ones, without repeating them', () => {
    expect(resolveCompanyIds(partialAdmin, { allowedCompanyIds })).toEqual(['company-1', 'company-2', 'company-3']);
    expect(resolveCompanyIds(client)).toEqual(['company-1']);
    expect(resolveCompanyIds(sales)).toEqual(['larvia']);
  });

  it('answers undefined, no filter, when the requester can access any company', () => {
    expect(resolveCompanyIds(larviaStaff)).toBeUndefined();
    expect(resolveCompanyIds(sales, { anyCompanyPermissions, allowedCompanyIds })).toBeUndefined();
  });

  it('rejects a token without company like the filter', () => {
    expect(() => resolveCompanyIds({ companyId: '', permissions: {} }, { allowedCompanyIds })).toThrow('This action requires a company to scope to.');
  });
});

describe('token without company', () => {
  const withoutCompany = { companyId: '', permissions: { companies: 'find:get:access-any:manage-any' } };

  it('is rejected like before, also with options', () => {
    const options = { anyCompanyPermissions, allowedCompanyIds: ['company-2'] };

    expect(() => resolveCompanyScope(withoutCompany, 'company-2', options)).toThrow('This action requires a company to scope to.');
    expect(() => resolveCompanyScope({ companyId: '', permissions: {} }, 'company-2', { allowedCompanyIds: ['company-2'] }))
      .toThrow(PermissionDeniedError);
    expect(() => resolveCompanyFilter({ companyId: '', permissions: {} }, { allowedCompanyIds: ['company-2'] }))
      .toThrow('This action requires a company to scope to.');
  });

  it('keeps the filter open for the staff that can access any company, like before', () => {
    expect(resolveCompanyFilter(withoutCompany)).toEqual({});
    expect(resolveCompanyFilter(withoutCompany, { anyCompanyPermissions })).toEqual({});
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
