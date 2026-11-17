import { roles } from '../commons';

import { CLIENT_VISIBLE_ROLE_KEYS, STAFF_ROLE_KEYS } from './role-templates';

// Where the lists come from, in lrv-auth-service:
// - STAFF_ROLE_KEYS: src/authorization/authorization.constants.ts. effective-permissions.ts uses it to mark a
//   legacy membership with a LarvIA role as internal.
// - CLIENT_VISIBLE_ROLE_KEYS: same file. withTemplateMetadata (src/roles/roles.service.ts) sets
//   `visibleToClients` on the templates of src/boot/data/roles.ts from it.
// A change there has to be made here too, and the other way around.
describe('role template lists', () => {
  it('lists the templates of the LarvIA team in the order of lrv-auth-service', () => {
    expect(STAFF_ROLE_KEYS).toEqual(['SUPER_ADMIN', 'PARTIAL_ADMIN', 'TECHNICAL_SUPPORT', 'SALES_MANAGER', 'SALES', 'FINANCE', 'TRADING']);
  });

  it('lists the templates company admins can assign (visibleToClients)', () => {
    expect(CLIENT_VISIBLE_ROLE_KEYS).toEqual(['CLIENT_MANAGER', 'CLIENT_OPERATOR', 'PARAMETERIST']);
  });

  it('leaves the owner template out of both lists', () => {
    expect(STAFF_ROLE_KEYS).not.toContain(roles.CLIENT_OWNER);
    expect(CLIENT_VISIBLE_ROLE_KEYS).not.toContain(roles.CLIENT_OWNER);
  });

  it('puts every role in exactly one group: staff, owner or assignable by company admins', () => {
    const grouped = [...STAFF_ROLE_KEYS, roles.CLIENT_OWNER, ...CLIENT_VISIBLE_ROLE_KEYS];

    expect(new Set(grouped).size).toBe(grouped.length);
    expect([...grouped].sort()).toEqual(Object.values(roles).sort());
  });

  it('cannot be changed at runtime', () => {
    expect(Object.isFrozen(STAFF_ROLE_KEYS)).toBe(true);
    expect(Object.isFrozen(CLIENT_VISIBLE_ROLE_KEYS)).toBe(true);
  });

  it('is read-only for the compiler too', () => {
    // @ts-expect-error the lists are read-only
    expect(() => STAFF_ROLE_KEYS.push(roles.CLIENT_OWNER)).toThrow(TypeError);
    // @ts-expect-error the lists are read-only
    expect(() => CLIENT_VISIBLE_ROLE_KEYS.push(roles.CLIENT_OWNER)).toThrow(TypeError);
  });
});
