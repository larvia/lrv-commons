export const roles = {
  SUPER_ADMIN: "SUPER_ADMIN",
  ADMIN: "ADMIN",
  CLIENT_OWNER: "CLIENT_OWNER",
  CLIENT_MEMBER: "CLIENT_MEMBER"
};

export function getHigherRole(userRoles: Array<String>) {
  const rolesScore = {
    [roles.SUPER_ADMIN]: 5,
    [roles.ADMIN]: 4,
    [roles.CLIENT_OWNER]: 3,
    [roles.CLIENT_MEMBER]: 2
  };
  const scores = userRoles.map((r: any) => rolesScore[r]);
  const higherRoleScore = Math.max(...scores);
  const higherRoleIndex = Object.values(rolesScore).indexOf(higherRoleScore);
  return Object.keys(rolesScore)[higherRoleIndex];
}
