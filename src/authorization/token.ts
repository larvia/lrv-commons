import { AccessTokenPayload } from './types';

/** What the access token of a user must carry. */
export interface AccessTokenRules {
  /** `alg` of the header. */
  algorithm: string;
  /** `aud` claim. */
  audience: string;
  /** `iss` claim, compared with case. */
  issuer: string;
}

/** How lrv-auth-service signs the access tokens. */
export const DEFAULT_ACCESS_TOKEN_RULES: Readonly<AccessTokenRules> = Object.freeze({
  algorithm: 'HS256',
  audience: 'https://larvia.ai',
  issuer: 'Larvia',
});

/** Why a token is invalid. Log or answer only this, never the token. */
export const ACCESS_TOKEN_REJECTION_REASONS = Object.freeze([
  // The header or the claims are not objects, or a claim has the wrong type.
  'malformed',
  'unsupportedAlgorithm',
  // User claims (`roles` or the user `aud`) without `sub`.
  'missingSubject',
  'missingAudience',
  'invalidAudience',
  'missingIssuer',
  'invalidIssuer',
  'missingExpiration',
  'expired',
] as const);

export type AccessTokenRejectionReason = typeof ACCESS_TOKEN_REJECTION_REASONS[number];

/**
 * `user`: a token issued by lrv-auth-service. `integration`: no `sub`, no `roles` and not the user `aud`,
 * like the API keys; each service decides whether it accepts that channel.
 */
export type AccessTokenClassification =
  | { kind: 'user' }
  | { kind: 'integration' }
  | { kind: 'invalid'; reason: AccessTokenRejectionReason };

/** Header and claims of a token whose signature Feathers already verified. */
export interface DecodedAccessToken {
  header: unknown;
  payload: unknown;
}

export interface ClassifyAccessTokenOptions extends Partial<AccessTokenRules> {
  /** Current time in milliseconds. Default: `Date.now()`. */
  nowMs?: number;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isMissing = (value: unknown) => value === undefined || value === null;

const invalid = (reason: AccessTokenRejectionReason): AccessTokenClassification => ({ kind: 'invalid', reason });

const hasAudience = (aud: unknown, audience: string) => aud === audience || (Array.isArray(aud) && aud.includes(audience));

/**
 * Tells a user token from the integration channel, or why the token is invalid. The algorithm is checked
 * for every token; a user token (with `sub`) must also carry the expected `aud`, `iss` and an `exp` still
 * in the future, and a token with the user `aud` must carry `sub`. It does not verify the signature: run
 * it after Feathers did.
 */
export const classifyAccessToken = (
  token: DecodedAccessToken | null | undefined,
  options: ClassifyAccessTokenOptions = {},
): AccessTokenClassification => {
  const algorithm = options.algorithm ?? DEFAULT_ACCESS_TOKEN_RULES.algorithm;
  const audience = options.audience ?? DEFAULT_ACCESS_TOKEN_RULES.audience;
  const issuer = options.issuer ?? DEFAULT_ACCESS_TOKEN_RULES.issuer;
  const nowSeconds = Math.floor((options.nowMs ?? Date.now()) / 1000);
  const header = token?.header;
  const payload = token?.payload;

  if (!isObject(header) || !isObject(payload)) {
    return invalid('malformed');
  }

  if (header.alg !== algorithm) {
    return invalid('unsupportedAlgorithm');
  }

  const { sub, roles, aud, iss, exp } = payload;

  if (!isMissing(exp) && !Number.isFinite(exp)) {
    return invalid('malformed');
  }

  // Expired in both channels; a clock that is not a number counts as expired.
  if (typeof exp === 'number' && !(nowSeconds < exp)) {
    return invalid('expired');
  }

  if (isMissing(sub)) {
    // Other tokens of lrv-auth-service, such as the refresh token, carry the user `aud` without `sub`.
    return isMissing(roles) && !hasAudience(aud, audience) ? { kind: 'integration' } : invalid('missingSubject');
  }

  if (typeof sub !== 'string' || !sub) {
    return invalid('malformed');
  }

  if (isMissing(aud)) {
    return invalid('missingAudience');
  }

  if (!hasAudience(aud, audience)) {
    return invalid('invalidAudience');
  }

  if (isMissing(iss)) {
    return invalid('missingIssuer');
  }

  if (iss !== issuer) {
    return invalid('invalidIssuer');
  }

  if (isMissing(exp)) {
    return invalid('missingExpiration');
  }

  return { kind: 'user' };
};

/** Version of a membership without a `user-companies` document, and of a token without `mv`. */
export const DEFAULT_MEMBERSHIP_VERSION = 0;

/** Reason of the 401 a service answers when `isTokenOutdated` is true. */
export const TOKEN_OUTDATED_REASON = 'tokenOutdated';

/** Reason of a 401 for the token: one of `classifyAccessToken`, or `tokenOutdated`. */
export type TokenRejectionReason = AccessTokenRejectionReason | typeof TOKEN_OUTDATED_REASON;

/**
 * Whether the token was issued for another version of the membership. `currentVersion` is the version of
 * the membership document, or nothing when there is no document. When true, answer 401 `tokenOutdated`
 * (`new TokenRejectedError(TOKEN_OUTDATED_REASON)`) so the client gets a new token.
 */
export const isTokenOutdated = (
  payload: Partial<AccessTokenPayload> | null | undefined,
  currentVersion?: number | null,
): boolean => {
  const issued = payload?.mv ?? DEFAULT_MEMBERSHIP_VERSION;
  const current = currentVersion ?? DEFAULT_MEMBERSHIP_VERSION;

  return !(Number.isFinite(issued) && issued === current);
};
