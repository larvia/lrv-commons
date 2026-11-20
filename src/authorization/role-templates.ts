import { roles } from '../commons';

// Same lists as lrv-auth-service, which uses them for the seeded templates: change both together.

/** Role templates of the LarvIA team. A legacy membership (built from the user) with one of them is internal. */
export const STAFF_ROLE_KEYS: readonly string[] = Object.freeze([
  roles.SUPER_ADMIN, roles.PARTIAL_ADMIN, roles.SALES_MANAGER, roles.SALES, roles.FINANCE, roles.TRADING,
]);

/** Templates company admins can assign to their users (`visibleToClients`). The owner template is not one of them. */
export const CLIENT_VISIBLE_ROLE_KEYS: readonly string[] = Object.freeze([roles.CLIENT_MANAGER, roles.CLIENT_OPERATOR, roles.PARAMETERIST]);
