// The "self" rule: the request works on the caller's own account. Ids are compared as text, so a Mongo ObjectId
// and its hex string match. A token without `sub` (an API key) is never the caller's own account.

// Mongo reads ObjectId hex in any case, so '5F8D...' and '5f8d...' are the same account and must match here too.
const OBJECT_ID_HEX = /^[0-9a-f]{24}$/i;
const normalizeId = (id: string) => (OBJECT_ID_HEX.test(id) ? id.toLowerCase() : id);

// An ObjectId stringifies to its hex; any other object (an operator such as { $ne: 'x' }) never matches.
const isObjectIdLike = (value: object) => typeof (value as { toHexString?: unknown }).toHexString === 'function';

/** True when `targetId` is the account of the token owner `sub`. */
export const isSameUser = (targetId: unknown, sub: unknown): boolean => {
  if (sub === undefined || sub === null || String(sub) === '') {
    return false;
  }

  if (targetId === undefined || targetId === null || (typeof targetId === 'object' && !isObjectIdLike(targetId))) {
    return false;
  }

  return normalizeId(String(targetId)) === normalizeId(String(sub));
};
