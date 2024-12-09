export const roles = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  PARTIAL_ADMIN: 'PARTIAL_ADMIN',
  SALES: 'SALES',
  SALES_MANAGER: 'SALES_MANAGER',
  PROMOTER: 'PROMOTER',
  BUSINESS_MANAGER: 'BUSINESS_MANAGER',
  CLIENT_OWNER: 'CLIENT_OWNER',
  CLIENT_MANAGER: 'CLIENT_MANAGER',
  CLIENT_OPERATOR: 'CLIENT_OPERATOR',
  PARAMETERIST: 'PARAMETERIST',
  FINANCE: 'FINANCE',
  TRADING: 'TRADING',
  TECHNICAL_SUPPORT: 'TECHNICAL_SUPPORT',
};

export function getHigherRole (userRoles: Array<String>) {
  const rolesScore = {
    [roles.SUPER_ADMIN]: 13,
    [roles.PARTIAL_ADMIN]: 12,
    [roles.TECHNICAL_SUPPORT]: 11,
    [roles.SALES_MANAGER]: 10,
    [roles.SALES]: 9,
    [roles.PROMOTER]: 8,
    [roles.BUSINESS_MANAGER]: 7,
    [roles.CLIENT_OWNER]: 6,
    [roles.CLIENT_MANAGER]: 5,
    [roles.CLIENT_OPERATOR]: 4,
    [roles.PARAMETERIST]: 3,
    [roles.FINANCE]: 2,
    [roles.TRADING]: 1,
  };
  const scores = userRoles.map((r: any) => rolesScore[r]);
  const higherRoleScore = Math.max(...scores);
  const higherRoleIndex = Object.values(rolesScore).indexOf(higherRoleScore);
  return Object.keys(rolesScore)[higherRoleIndex];
}

export const languages = {
  ES: 'Español',
  EN: 'English'
}

export const analysisTypes = [
  'GENERAL_LARVAE_ANALYSIS'
]

export const larvaeSpecies = [
  'LITOPENAEUS_VANNAMEI'
]
