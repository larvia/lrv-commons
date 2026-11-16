/** A permission is `modelName:action`, for example `stockings:create` or `stockings:download-report`. */
export type PermissionKey = string;

/**
 * `permissions` claim of the access token issued by lrv-auth-service: model name → actions joined by `:`.
 * Example: `{ stockings: 'find:get:create', analysis: 'find' }`.
 */
export type PermissionsMap = Record<string, string>;

export interface TokenActor {
  /** Id of the LarvIA user who is impersonating the token owner. */
  sub: string;
  expiresAtMs: number;
}

/**
 * Claims of the access token. `roles`, `permissions` and `companyId` keep the format of the first version,
 * so services that still read them keep working; the rest were added for permissions by company.
 */
export interface AccessTokenPayload {
  sub: string;
  /** Company the session works on (chosen at login or when switching company). */
  companyId: string;
  /** Legacy: key of the role template of the membership. Do not use it to authorize. */
  roles: string[];
  /** Effective permissions of the user in the active company. */
  permissions: PermissionsMap;
  /** The membership sees every unit, module and container of the company, including future ones. */
  accessAll?: boolean;
  isOwner?: boolean;
  /** LarvIA staff session (membership in the LarvIA company). */
  internal?: boolean;
  /** Membership version, to detect tokens issued before a permission change. */
  mv?: number;
  act?: TokenActor;
  email?: string;
  firstName?: string;
  lastName?: string;
  language?: string;
  active?: boolean;
  iat?: number;
  exp?: number;
}

/** Units/modules/containers a membership can see in its company. */
export interface ModuleScope {
  accessAll: boolean;
  moduleIds: string[];
}
