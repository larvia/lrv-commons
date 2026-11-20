import { getHigherRole, roles } from './commons';

describe('getHigherRole', () => {
  it('returns the role with the highest score', () => {
    expect(getHigherRole([roles.CLIENT_OPERATOR, roles.SALES, roles.FINANCE])).toBe(roles.SALES);
  });

  it('ignores a retired role that an old token still carries', () => {
    expect(getHigherRole(['TECHNICAL_SUPPORT', roles.FINANCE])).toBe(roles.FINANCE);
  });

  it('returns undefined when every role is retired', () => {
    expect(getHigherRole(['TECHNICAL_SUPPORT'])).toBeUndefined();
  });

  it('no longer lists TECHNICAL_SUPPORT', () => {
    expect(roles).not.toHaveProperty('TECHNICAL_SUPPORT');
  });
});
