import { Reflector } from '@nestjs/core';
import { CanActivate, ExecutionContext, ForbiddenException, Injectable, SetMetadata } from '@nestjs/common';

import { hasPermission, parsePermissionKey } from '../permissions';
import { PermissionKey, PermissionsMap } from '../types';

export const REQUIRED_PERMISSIONS_KEY = 'lrv:required-permissions';

/** Declares the permissions an endpoint (or every endpoint of a controller) requires. */
export const RequirePermissions = (...keys: PermissionKey[]) => {
  keys.forEach(parsePermissionKey);
  return SetMetadata(REQUIRED_PERMISSIONS_KEY, keys);
};

/** The JWT strategy may leave the claims in `request.user` or in `request.authentication.payload`. */
const getPermissions = (request: any): PermissionsMap | undefined =>
  request?.user?.permissions ?? request?.authentication?.payload?.permissions;

/**
 * Deny-by-default guard: an endpoint without `@RequirePermissions` is rejected, so a new endpoint cannot
 * be left open by mistake. Use it after the JWT guard: `@UseGuards(JwtAuthGuard, PermissionsGuard)`.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) { }

  canActivate(context: ExecutionContext): boolean {
    const keys = this.reflector.getAllAndOverride<PermissionKey[]>(REQUIRED_PERMISSIONS_KEY, [context.getHandler(), context.getClass()]);

    if (!keys?.length) {
      throw new ForbiddenException('This endpoint does not declare the permissions it requires.');
    }

    const permissions = getPermissions(context.switchToHttp().getRequest());
    if (keys.some((key) => !hasPermission(permissions, key))) {
      throw new ForbiddenException('You do not have the correct permissions.');
    }

    return true;
  }
}
