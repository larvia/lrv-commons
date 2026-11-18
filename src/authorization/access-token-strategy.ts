import { TokenRejectedError } from './errors';
import { AccessTokenPayload } from './types';
import { classifyAccessToken, DecodedAccessToken, isTokenOutdated, TOKEN_OUTDATED_REASON, TokenRejectionReason } from './token';

/** 'log' lets every token Feathers accepts through and logs why it would be rejected; 'enforce' answers 401. */
export type TokenCheckMode = 'log' | 'enforce';

/** Any value other than 'enforce', or no value, keeps the log mode, so a typo never starts rejecting tokens. */
export const parseTokenCheckMode = (value: string | undefined): TokenCheckMode => (value === 'enforce' ? 'enforce' : 'log');

/** Current version of the caller's membership, or nothing when there is no membership document. */
export type MembershipVersionReader = (payload: Partial<AccessTokenPayload>) => Promise<number | null | undefined>;

/** No membership version is known: every token passes the `mv` check. */
export const noMembershipVersion: MembershipVersionReader = async () => undefined;

const decodePart = (part: string | undefined): unknown => {
  if (!part) {
    return undefined;
  }

  try {
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
};

/** Header and claims of a JWT, without verifying it: use it only after Feathers verified the signature. */
export const decodeAccessToken = (accessToken: unknown): DecodedAccessToken | null => {
  if (typeof accessToken !== 'string') {
    return null;
  }

  const [header, payload] = accessToken.split('.');
  return { header: decodePart(header), payload: decodePart(payload) };
};

export interface TokenCheckOptions {
  getMembershipVersion?: MembershipVersionReader;
  /** Accept the integration channel (no `sub`, like the API keys). Default: rejected as `missingSubject`. */
  acceptIntegration?: boolean;
}

/** Why a service would reject a token whose signature and expiry Feathers already verified, or null. */
export const findTokenRejectionReason = async (
  accessToken: string,
  payload: Partial<AccessTokenPayload>,
  options: TokenCheckOptions = {},
): Promise<TokenRejectionReason | null> => {
  const classification = classifyAccessToken(decodeAccessToken(accessToken));

  if (classification.kind === 'invalid') {
    return classification.reason;
  }

  if (classification.kind === 'integration') {
    return options.acceptIntegration ? null : 'missingSubject';
  }

  const getMembershipVersion = options.getMembershipVersion ?? noMembershipVersion;
  return isTokenOutdated(payload, await getMembershipVersion(payload)) ? TOKEN_OUTDATED_REASON : null;
};

/** What to log for a rejected token: the reason and who sent it. Never the token or the headers. */
export const describeRejectedToken = (props: {
  reason: TokenRejectionReason;
  mode: TokenCheckMode;
  payload?: Partial<AccessTokenPayload> & { iss?: unknown; aud?: unknown };
  userAgent?: unknown;
}) => ({
  mode: props.mode,
  reason: props.reason,
  sub: props.payload?.sub,
  companyId: props.payload?.companyId,
  iss: props.payload?.iss,
  aud: props.payload?.aud,
  userAgent: typeof props.userAgent === 'string' ? props.userAgent : undefined,
});

export interface TokenCheckLogger {
  warn(message: string, ...args: unknown[]): unknown;
}

export interface AccessTokenStrategyOptions extends TokenCheckOptions {
  mode?: TokenCheckMode;
  logger: TokenCheckLogger;
}

/** The part of what `JWTStrategy.authenticate` of Feathers resolves that the checks read. */
export interface JwtAuthenticationResult {
  accessToken: string;
  authentication: { payload: Partial<AccessTokenPayload> };
}

/* eslint-disable @typescript-eslint/no-explicit-any */
// Feathers types its strategies loosely (`authenticate(...): Promise<any>`); the mixin keeps the base's signature.
interface JwtStrategyLike {
  authenticate(authentication: any, params: any): Promise<any>;
}

type StrategyClass = new (...args: any[]) => JwtStrategyLike;
/* eslint-enable @typescript-eslint/no-explicit-any */

/**
 * The 'jwt' strategy with the LD-62 token checks, from the `JWTStrategy` class of the service. Register it on the
 * AuthenticationService: `authentication.register('jwt', new (withAccessTokenChecks(JWTStrategy, { mode, logger }))())`.
 * Feathers still checks the signature and the expiry (same 401 as before); then the token must look like one issued
 * by lrv-auth-service. In log mode it only logs the reason; in enforce mode it answers 401 with `TokenRejectedError`.
 * The result keeps the type of the base, so a service can extend the class and override `authenticate`.
 */
export const withAccessTokenChecks = <TBase extends StrategyClass>(Base: TBase, options: AccessTokenStrategyOptions) => {
  const mode = options.mode ?? 'log';

  const check = async (result: JwtAuthenticationResult, params: { headers?: Record<string, unknown> } | undefined) => {
    const { payload } = result.authentication;
    const reason = await findTokenRejectionReason(result.accessToken, payload, options);

    if (reason) {
      const details = describeRejectedToken({ reason, mode, payload, userAgent: params?.headers?.['user-agent'] });
      options.logger.warn('Access token check: %s', JSON.stringify(details));

      if (mode === 'enforce') {
        throw new TokenRejectedError(reason);
      }
    }

    return result;
  };

  return class AccessTokenStrategy extends Base {
    authenticate(...args: Parameters<InstanceType<TBase>['authenticate']>): ReturnType<InstanceType<TBase>['authenticate']> {
      const [authentication, params] = args;
      return super.authenticate(authentication, params).then((result: JwtAuthenticationResult) => check(result, params)) as ReturnType<InstanceType<TBase>['authenticate']>;
    }
  };
};
