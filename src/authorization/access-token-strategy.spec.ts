import { TokenRejectedError } from './errors';
import {
  decodeAccessToken,
  describeRejectedToken,
  findTokenRejectionReason,
  parseTokenCheckMode,
  TokenCheckMode,
  withAccessTokenChecks,
} from './access-token-strategy';

const NOW_SECONDS = Math.floor(Date.now() / 1000);

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

// Unsigned: these checks run after Feathers verified the signature.
const buildToken = (claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'HS256', typ: 'access' }) =>
  `${encode(header)}.${encode(claims)}.signature`;

const userClaims = (extra: Record<string, unknown> = {}) => ({
  sub: '5001',
  companyId: 'c-1',
  roles: ['CLIENT_OWNER'],
  permissions: {},
  aud: 'https://larvia.ai',
  iss: 'Larvia',
  exp: NOW_SECONDS + 3600,
  ...extra,
});

describe('parseTokenCheckMode', () => {
  it('enforces only for the exact value "enforce"', () => {
    expect(parseTokenCheckMode('enforce')).toBe('enforce');
    expect(parseTokenCheckMode('ENFORCE')).toBe('log');
    expect(parseTokenCheckMode('log')).toBe('log');
    expect(parseTokenCheckMode(undefined)).toBe('log');
  });
});

describe('decodeAccessToken', () => {
  it('reads the header and the claims', () => {
    expect(decodeAccessToken(buildToken({ sub: '5001' }))).toEqual({ header: { alg: 'HS256', typ: 'access' }, payload: { sub: '5001' } });
  });

  it('leaves a part it cannot read undefined, and anything that is not text null', () => {
    expect(decodeAccessToken('not-a-jwt')).toEqual({ header: undefined, payload: undefined });
    expect(decodeAccessToken(undefined)).toBeNull();
  });
});

describe('findTokenRejectionReason', () => {
  const check = (claims: Record<string, unknown>, options = {}, header?: Record<string, unknown>) =>
    findTokenRejectionReason(buildToken(claims, header), claims, options);

  it('accepts a token of lrv-auth-service', async () => {
    await expect(check(userClaims())).resolves.toBeNull();
  });

  it.each([
    [{ aud: undefined }, 'missingAudience'],
    [{ aud: 'https://other.example' }, 'invalidAudience'],
    [{ iss: 'larvia' }, 'invalidIssuer'],
    [{ iss: undefined }, 'missingIssuer'],
    [{ exp: undefined }, 'missingExpiration'],
  ])('rejects a token with %j as %s', async (extra, reason) => {
    await expect(check(userClaims(extra))).resolves.toBe(reason);
  });

  it('rejects another algorithm', async () => {
    await expect(check(userClaims(), {}, { alg: 'HS512' })).resolves.toBe('unsupportedAlgorithm');
  });

  it('rejects the integration channel unless the service accepts it', async () => {
    const integration = { companyId: 'c-1', exp: NOW_SECONDS + 3600 };

    await expect(check(integration)).resolves.toBe('missingSubject');
    await expect(check(integration, { acceptIntegration: true })).resolves.toBeNull();
  });

  it('flags tokenOutdated when the membership has another version', async () => {
    const getMembershipVersion = jest.fn().mockResolvedValue(3);

    await expect(check(userClaims({ mv: 2 }), { getMembershipVersion })).resolves.toBe('tokenOutdated');
    await expect(check(userClaims({ mv: 3 }), { getMembershipVersion })).resolves.toBeNull();
  });
});

describe('describeRejectedToken', () => {
  it('keeps who sent it and never the token', () => {
    const details = describeRejectedToken({ reason: 'invalidIssuer', mode: 'log', payload: userClaims({ iss: 'larvia' }), userAgent: 'app/1.0' });

    expect(details).toEqual({ mode: 'log', reason: 'invalidIssuer', sub: '5001', companyId: 'c-1', iss: 'larvia', aud: 'https://larvia.ai', userAgent: 'app/1.0' });
  });
});

describe('withAccessTokenChecks', () => {
  const logger = { warn: jest.fn() };

  // The shape `JWTStrategy.authenticate` of Feathers 4 resolves.
  interface FeathersAuthenticationResult {
    accessToken: string;
    authentication: { strategy: string; accessToken: string; payload: Record<string, unknown> };
  }

  // Stands in for the JWTStrategy of Feathers, which already verified the signature and the expiry.
  class FakeJwtStrategy {
    calls: unknown[] = [];

    async authenticate(authentication: { accessToken: string }, params: Record<string, unknown>): Promise<FeathersAuthenticationResult> {
      this.calls.push(params);
      const [, claims] = authentication.accessToken.split('.');
      const payload = JSON.parse(Buffer.from(claims, 'base64url').toString());
      return { accessToken: authentication.accessToken, authentication: { strategy: 'jwt', accessToken: authentication.accessToken, payload } };
    }
  }

  const authenticateWith = (mode: TokenCheckMode, accessToken: string) => {
    const Strategy = withAccessTokenChecks(FakeJwtStrategy, { mode, logger });
    return new Strategy().authenticate({ accessToken }, { headers: { 'user-agent': 'app/1.0', authorization: accessToken } });
  };

  beforeEach(() => {
    logger.warn.mockClear();
  });

  describe.each(['log', 'enforce'] as TokenCheckMode[])('in %s mode', (mode) => {
    it('accepts a token of lrv-auth-service without logging', async () => {
      const accessToken = buildToken(userClaims());

      await expect(authenticateWith(mode, accessToken)).resolves.toMatchObject({ accessToken });
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('logs the reason of a rejected token, never the token', async () => {
      const accessToken = buildToken(userClaims({ iss: 'larvia' }));

      await authenticateWith(mode, accessToken).catch(() => null);

      expect(logger.warn).toHaveBeenCalledTimes(1);
      const logged = JSON.stringify(logger.warn.mock.calls[0]);
      expect(logged).toContain('invalidIssuer');
      expect(logged).toContain('app/1.0');
      expect(logged).not.toContain(accessToken.split('.')[1]);
    });
  });

  it('lets a rejected token through in log mode', async () => {
    await expect(authenticateWith('log', buildToken(userClaims({ aud: undefined })))).resolves.toBeDefined();
  });

  it('answers 401 with the reason in enforce mode', async () => {
    const call = authenticateWith('enforce', buildToken(userClaims({ aud: undefined })));

    await expect(call).rejects.toBeInstanceOf(TokenRejectedError);
    await expect(authenticateWith('enforce', buildToken(userClaims({ aud: undefined })))).rejects.toMatchObject({ code: 401, data: { reason: 'missingAudience' } });
  });

  it('defaults to the log mode', async () => {
    const Strategy = withAccessTokenChecks(FakeJwtStrategy, { logger });

    await expect(new Strategy().authenticate({ accessToken: buildToken(userClaims({ aud: undefined })) }, {})).resolves.toBeDefined();
  });

  it('lets a service extend the strategy and override authenticate', async () => {
    // Declaring the Feathers result type pins that the mixin keeps the base's return type (it does not compile otherwise).
    class ServiceStrategy extends withAccessTokenChecks(FakeJwtStrategy, { mode: 'enforce', logger }) {
      async authenticate(authentication: { accessToken: string }, params: Record<string, unknown>): Promise<FeathersAuthenticationResult & { checkedBy: string }> {
        const result = await super.authenticate(authentication, params);
        const strategy: string = result.authentication.strategy;
        return { ...result, checkedBy: `service:${strategy}` };
      }
    }

    await expect(new ServiceStrategy().authenticate({ accessToken: buildToken(userClaims()) }, {})).resolves.toMatchObject({ checkedBy: 'service:jwt' });
    await expect(new ServiceStrategy().authenticate({ accessToken: buildToken(userClaims({ iss: 'larvia' })) }, {})).rejects.toBeInstanceOf(TokenRejectedError);
  });

  it('keeps the error of Feathers for a token it rejects', async () => {
    class ExpiredStrategy {
      async authenticate(_authentication: unknown, _params: unknown): Promise<never> {
        throw Object.assign(new Error('jwt expired'), { code: 401 });
      }
    }
    const Strategy = withAccessTokenChecks(ExpiredStrategy, { mode: 'enforce', logger });

    await expect(new Strategy().authenticate({}, {})).rejects.toMatchObject({ message: 'jwt expired', code: 401 });
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
