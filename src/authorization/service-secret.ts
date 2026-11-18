import { timingSafeEqual } from 'crypto';

/**
 * True when the credential is the secret LarvIA services send each other (`AUTHENTICATION_SECRET_SERVICE`). Pass the
 * credential Feathers parsed from the Authorization header (`req.authentication.accessToken`). Without a configured
 * secret nothing matches. The comparison takes the same time whatever the credential; only its length leaks.
 */
export const isServiceSecret = (credential: unknown, secret: string | undefined): boolean => {
  if (!secret || typeof credential !== 'string') {
    return false;
  }

  const expected = Buffer.from(secret);
  const received = Buffer.from(credential);

  return expected.length === received.length && timingSafeEqual(expected, received);
};
