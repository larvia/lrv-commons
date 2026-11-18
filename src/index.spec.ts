// The root entry must work without Nest: loading @nestjs/* from it fails this suite.
jest.mock('@nestjs/common', () => {
  throw new Error('The root entry loaded @nestjs/common.');
});
jest.mock('@nestjs/core', () => {
  throw new Error('The root entry loaded @nestjs/core.');
});

import * as root from './index';
import * as authorization from './authorization';

describe('root entry', () => {
  const previousExports = [
    'getHigherRole', 'roles', 'languages', 'analysisTypes', 'larvaeSpecies', 'PermissionDeniedError', 'toPermissionKey',
    'parsePermissionKey', 'getGrantedActions', 'hasPermission', 'hasAnyPermission', 'hasAllPermissions', 'assertPermissions',
    'assertPermission', 'assertAnyPermission', 'ACCESS_ANY_COMPANY_PERMISSION', 'resolveCompanyScope', 'resolveCompanyFilter',
    'canAccessModule', 'resolveModuleFilter', 'authorize', 'authorizeAny', 'requirePermissions',
  ];
  const additions = [
    'requireAnyPermission', 'MANAGE_ANY_COMPANY_PERMISSION', 'classifyAccessToken', 'DEFAULT_ACCESS_TOKEN_RULES',
    'ACCESS_TOKEN_REJECTION_REASONS', 'isTokenOutdated', 'DEFAULT_MEMBERSHIP_VERSION', 'TOKEN_OUTDATED_REASON',
    'STAFF_ROLE_KEYS', 'CLIENT_VISIBLE_ROLE_KEYS', 'resolveCompanyIds', 'TokenRejectedError',
    // 1.3.0
    'policy', 'defineServicePolicies', 'describePolicy', 'SERVICE_METHODS', 'createServicePolicyHook', 'createSecureRoute',
    'listRoutePolicies', 'ROUTE_POLICY', 'withAccessTokenChecks', 'findTokenRejectionReason', 'decodeAccessToken',
    'describeRejectedToken', 'parseTokenCheckMode', 'noMembershipVersion', 'isSameUser', 'isServiceSecret',
    'NotAuthenticatedError', 'MethodNotAllowedError', 'isFeathersLikeError',
  ];

  it.each(previousExports)('keeps exporting %s', (name) => {
    expect(root).toHaveProperty(name);
  });

  it.each(additions)('exports %s from the root and from the authorization module', (name) => {
    expect((root as Record<string, unknown>)[name]).toBeDefined();
    expect((root as Record<string, unknown>)[name]).toBe((authorization as Record<string, unknown>)[name]);
  });
});
