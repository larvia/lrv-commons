export const roles = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  SALES: 'SALES',
  CLIENT_OWNER: 'CLIENT_OWNER',
  CLIENT_MANAGER: 'CLIENT_MANAGER',
  CLIENT_OPERATOR: 'CLIENT_OPERATOR',
};

export function getHigherRole(userRoles: Array<String>) {
  const rolesScore = {
    [roles.SUPER_ADMIN]: 5,
    [roles.SALES]: 4,
    [roles.CLIENT_OWNER]: 3,
    [roles.CLIENT_MANAGER]: 2,
    [roles.CLIENT_OPERATOR]: 1
  };
  const scores = userRoles.map((r: any) => rolesScore[r]);
  const higherRoleScore = Math.max(...scores);
  const higherRoleIndex = Object.values(rolesScore).indexOf(higherRoleScore);
  return Object.keys(rolesScore)[higherRoleIndex];
}

export const languages = {
  ES : 'Español',
  EN : 'English'
}


export const analysisTypes = [
  'GENERAL_LARVAE_ANALYSIS'
  ]

export const larvaeSpecies = [
  'LITOPENAEUS_VANNAMEI'
]
