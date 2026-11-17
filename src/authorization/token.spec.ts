import { TokenRejectedError } from './errors';
import {
  ACCESS_TOKEN_REJECTION_REASONS, AccessTokenClassification, AccessTokenRejectionReason, DEFAULT_ACCESS_TOKEN_RULES,
  DEFAULT_MEMBERSHIP_VERSION, TOKEN_OUTDATED_REASON, classifyAccessToken, isTokenOutdated,
} from './token';
import { AccessTokenPayload } from './types';

const NOW_MS = Date.UTC(2026, 10, 17, 12, 0, 0);
const NOW_SECONDS = NOW_MS / 1000;
const header = { alg: 'HS256', typ: 'JWT' };

// Claims as lrv-auth-service signs them.
const userClaims: Record<string, unknown> = {
  sub: 'user-1',
  companyId: 'company-1',
  roles: ['CLIENT_OWNER'],
  permissions: { users: 'find:get' },
  mv: 0,
  iat: NOW_SECONDS - 60,
  exp: NOW_SECONDS + 4 * 3600,
  aud: 'https://larvia.ai',
  iss: 'Larvia',
};

// Claims of an integration API key: no sub, roles, aud, iss nor exp.
const apiKeyClaims: Record<string, unknown> = {
  companyId: 'company-1',
  permissions: { 'company-balances': 'find', payments: 'get' },
  iat: NOW_SECONDS - 60,
};

const classify = (payload: unknown, tokenHeader: unknown = header) =>
  classifyAccessToken({ header: tokenHeader, payload }, { nowMs: NOW_MS });

const userClaimsWith = (changes: Record<string, unknown>) => ({ ...userClaims, ...changes });

const userClaimsWithout = (claim: string) => {
  const claims = { ...userClaims };
  delete claims[claim];
  return claims;
};

describe('classifyAccessToken', () => {
  it('accepts a token of lrv-auth-service as a user token', () => {
    expect(classify(userClaims)).toEqual({ kind: 'user' });
  });

  it('uses the values lrv-auth-service signs with by default', () => {
    expect(DEFAULT_ACCESS_TOKEN_RULES).toEqual({ algorithm: 'HS256', audience: 'https://larvia.ai', issuer: 'Larvia' });
    expect(Object.isFrozen(DEFAULT_ACCESS_TOKEN_RULES)).toBe(true);
  });

  it('rejects a user token without aud or with another one', () => {
    expect(classify(userClaimsWithout('aud'))).toEqual({ kind: 'invalid', reason: 'missingAudience' });
    expect(classify(userClaimsWith({ aud: 'https://example.com' }))).toEqual({ kind: 'invalid', reason: 'invalidAudience' });
    expect(classify(userClaimsWith({ aud: [] }))).toEqual({ kind: 'invalid', reason: 'invalidAudience' });
  });

  it('accepts an aud list that includes the expected audience', () => {
    expect(classify(userClaimsWith({ aud: ['https://example.com', 'https://larvia.ai'] }))).toEqual({ kind: 'user' });
  });

  it('compares iss with case, so iss larvia is rejected', () => {
    expect(classify(userClaimsWith({ iss: 'larvia' }))).toEqual({ kind: 'invalid', reason: 'invalidIssuer' });
    expect(classify(userClaimsWithout('iss'))).toEqual({ kind: 'invalid', reason: 'missingIssuer' });
  });

  it('treats a token without sub, roles nor the user aud as the integration channel', () => {
    expect(classify(apiKeyClaims)).toEqual({ kind: 'integration' });
    expect(classify({ ...apiKeyClaims, aud: 'https://example.com' })).toEqual({ kind: 'integration' });
  });

  it('rejects user claims without sub', () => {
    expect(classify(userClaimsWithout('sub'))).toEqual({ kind: 'invalid', reason: 'missingSubject' });
    expect(classify(userClaimsWith({ sub: null, roles: [] }))).toEqual({ kind: 'invalid', reason: 'missingSubject' });
    expect(classify(userClaimsWith({ sub: undefined, roles: undefined }))).toEqual({ kind: 'invalid', reason: 'missingSubject' });
  });

  it('rejects a token with the user aud and without sub, like the other tokens of lrv-auth-service', () => {
    // Refresh token and password reset token, as lrv-auth-service signs them (with their own secrets).
    const signedClaims = { iat: NOW_SECONDS - 60, exp: NOW_SECONDS + 900, aud: 'https://larvia.ai', iss: 'Larvia' };
    const refreshClaims = { userId: 'user-1', companyId: 'company-1', ...signedClaims };
    const resetClaims = { userId: 'user-1', ...signedClaims };

    expect(classify(refreshClaims)).toEqual({ kind: 'invalid', reason: 'missingSubject' });
    expect(classify(resetClaims)).toEqual({ kind: 'invalid', reason: 'missingSubject' });
    expect(classify({ ...apiKeyClaims, aud: ['https://example.com', 'https://larvia.ai'] })).toEqual({ kind: 'invalid', reason: 'missingSubject' });
  });

  it('rejects an expired token, from the second exp is reached', () => {
    expect(classify(userClaimsWith({ exp: NOW_SECONDS - 1 }))).toEqual({ kind: 'invalid', reason: 'expired' });
    expect(classify(userClaimsWith({ exp: NOW_SECONDS }))).toEqual({ kind: 'invalid', reason: 'expired' });
    expect(classify(userClaimsWith({ exp: NOW_SECONDS + 1 }))).toEqual({ kind: 'user' });
  });

  it('rejects an expired token of the integration channel too', () => {
    expect(classify({ ...apiKeyClaims, exp: NOW_SECONDS - 1 })).toEqual({ kind: 'invalid', reason: 'expired' });
  });

  it('rejects another algorithm in both channels', () => {
    expect(classify(userClaims, { alg: 'HS512', typ: 'JWT' })).toEqual({ kind: 'invalid', reason: 'unsupportedAlgorithm' });
    expect(classify(userClaims, { alg: 'none' })).toEqual({ kind: 'invalid', reason: 'unsupportedAlgorithm' });
    expect(classify(userClaims, { alg: 'hs256' })).toEqual({ kind: 'invalid', reason: 'unsupportedAlgorithm' });
    expect(classify(userClaims, { typ: 'JWT' })).toEqual({ kind: 'invalid', reason: 'unsupportedAlgorithm' });
    expect(classify(apiKeyClaims, { alg: 'HS384' })).toEqual({ kind: 'invalid', reason: 'unsupportedAlgorithm' });
  });

  it('rejects a user token without exp', () => {
    expect(classify(userClaimsWithout('exp'))).toEqual({ kind: 'invalid', reason: 'missingExpiration' });
  });

  it('rejects a token that is not a decoded JWT or has claims of the wrong type', () => {
    expect(classifyAccessToken(null)).toEqual({ kind: 'invalid', reason: 'malformed' });
    expect(classify('not-an-object')).toEqual({ kind: 'invalid', reason: 'malformed' });
    expect(classify(userClaims, null)).toEqual({ kind: 'invalid', reason: 'malformed' });
    expect(classify([userClaims])).toEqual({ kind: 'invalid', reason: 'malformed' });
    expect(classify(userClaimsWith({ sub: 42 }))).toEqual({ kind: 'invalid', reason: 'malformed' });
    expect(classify(userClaimsWith({ sub: '' }))).toEqual({ kind: 'invalid', reason: 'malformed' });
    expect(classify(userClaimsWith({ exp: String(NOW_SECONDS + 60) }))).toEqual({ kind: 'invalid', reason: 'malformed' });
  });

  it('takes the expected values as options', () => {
    const options = { algorithm: 'HS512', audience: 'https://example.com', issuer: 'Example', nowMs: NOW_MS };
    const claims = userClaimsWith({ aud: 'https://example.com', iss: 'Example' });

    expect(classifyAccessToken({ header: { alg: 'HS512' }, payload: claims }, options)).toEqual({ kind: 'user' });
    expect(classifyAccessToken({ header, payload: userClaims }, options)).toEqual({ kind: 'invalid', reason: 'unsupportedAlgorithm' });
  });

  it('reads the clock when nowMs is not given', () => {
    const expiresSoon = userClaimsWith({ exp: Math.floor(Date.now() / 1000) + 60 });

    expect(classifyAccessToken({ header, payload: expiresSoon })).toEqual({ kind: 'user' });
    expect(classifyAccessToken({ header, payload: userClaimsWith({ exp: 1 }) })).toEqual({ kind: 'invalid', reason: 'expired' });
  });

  it('counts the token as expired when the clock given is not a number', () => {
    expect(classifyAccessToken({ header, payload: userClaims }, { nowMs: Number.NaN })).toEqual({ kind: 'invalid', reason: 'expired' });
  });

  describe('closed set of reasons', () => {
    const results: AccessTokenClassification[] = [
      classify(userClaims),
      classify(apiKeyClaims),
      classify('not-an-object'),
      classify(userClaims, { alg: 'HS512' }),
      classify(userClaimsWithout('sub')),
      classify(userClaimsWithout('aud')),
      classify(userClaimsWith({ aud: 'https://example.com' })),
      classify(userClaimsWithout('iss')),
      classify(userClaimsWith({ iss: 'larvia' })),
      classify(userClaimsWithout('exp')),
      classify(userClaimsWith({ exp: NOW_SECONDS - 1 })),
    ];

    it('produces every reason of the list and nothing else', () => {
      const reasons = results.flatMap((result) => (result.kind === 'invalid' ? [result.reason] : []));

      expect([...reasons].sort()).toEqual([...ACCESS_TOKEN_REJECTION_REASONS].sort());
    });

    it('never carries the token or its claims in the result', () => {
      results.forEach((result) => {
        expect(Object.keys(result).every((key) => key === 'kind' || key === 'reason')).toBe(true);
        expect(JSON.stringify(result)).not.toContain('user-1');
      });
    });

    it('types the reasons as a closed set', () => {
      // @ts-expect-error a reason outside the list
      const unknownReason: AccessTokenRejectionReason = 'somethingElse';

      expect(ACCESS_TOKEN_REJECTION_REASONS).not.toContain(unknownReason);
    });
  });
});

describe('isTokenOutdated', () => {
  it('passes when mv is the current version', () => {
    expect(isTokenOutdated({ mv: 3 }, 3)).toBe(false);
  });

  it('is outdated when mv is another version', () => {
    expect(isTokenOutdated({ mv: 2 }, 3)).toBe(true);
    expect(isTokenOutdated({ mv: 4 }, 3)).toBe(true);
  });

  it('compares with version 0 when the membership has no document', () => {
    expect(DEFAULT_MEMBERSHIP_VERSION).toBe(0);
    expect(isTokenOutdated({ mv: 0 }, undefined)).toBe(false);
    expect(isTokenOutdated({ mv: 0 }, null)).toBe(false);
    expect(isTokenOutdated({ mv: 1 }, undefined)).toBe(true);
  });

  it('counts a token without mv as version 0', () => {
    expect(isTokenOutdated({}, undefined)).toBe(false);
    expect(isTokenOutdated(undefined, 0)).toBe(false);
    expect(isTokenOutdated({}, 1)).toBe(true);
  });

  it('is outdated when mv is not a number', () => {
    expect(isTokenOutdated({ mv: '3' as unknown as number }, 3)).toBe(true);
    expect(isTokenOutdated({ mv: Number.NaN }, Number.NaN)).toBe(true);
  });

  it('accepts the payload types of the services, which have no mv claim', () => {
    const servicePayload: { companyId: string; sub: string; roles: string[] } = { companyId: 'company-1', sub: 'user-1', roles: [] };
    const adapterPayload: Partial<AccessTokenPayload> = { mv: 2 };

    expect(isTokenOutdated(servicePayload, 0)).toBe(false);
    expect(isTokenOutdated(servicePayload, 1)).toBe(true);
    expect(isTokenOutdated(adapterPayload, 2)).toBe(false);
  });

  it('names the reason of the 401', () => {
    expect(TOKEN_OUTDATED_REASON).toBe('tokenOutdated');
  });
});

describe('TokenRejectedError', () => {
  it('is a 401 with the shape of a Feathers error and the reason in data', () => {
    const error = new TokenRejectedError(TOKEN_OUTDATED_REASON);

    expect(error).toBeInstanceOf(TokenRejectedError);
    expect(error).toBeInstanceOf(Error);
    expect(error.type).toBe('FeathersError');
    expect(error.toJSON()).toEqual({
      name: 'NotAuthenticated',
      message: 'The access token was rejected.',
      code: 401,
      className: 'not-authenticated',
      data: { reason: 'tokenOutdated' },
      errors: {},
    });
  });

  it('carries a reason of classifyAccessToken and an optional message', () => {
    const result = classify(userClaimsWithout('aud'));
    const error = new TokenRejectedError(result.kind === 'invalid' ? result.reason : 'malformed', 'Invalid access token.');

    expect(error.message).toBe('Invalid access token.');
    expect(error.data).toEqual({ reason: 'missingAudience' });
  });
});
