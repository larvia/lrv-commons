import { rolesNames as roles } from "./data/roles";


export function getHigherRole(userRoles: Array<String>) {
    const rolesScore = {
        [roles.SUPER_ADMIN]: 5,
        [roles.ADMIN]: 4,
        [roles.CLIENT_OWNER]: 3,
        [roles.CLIENT_MEMBER]: 2,
    };
    const scores = userRoles.map((r: any) => rolesScore[r]);
    const higherRoleScore = Math.max(...scores);
    const higherRoleIndex = Object.values(rolesScore).indexOf(higherRoleScore);
    return Object.keys(rolesScore)[higherRoleIndex];
}