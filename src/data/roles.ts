export const rolesNames = {
    SUPER_ADMIN: 'SUPER_ADMIN',
    ADMIN: 'ADMIN',
    CLIENT_OWNER: 'CLIENT_OWNER',
    CLIENT_MEMBER: 'CLIENT_MEMBER',
};

export const roles = [
    {
        _id: '5e228978ab559e56783edaaa',
        name: rolesNames.SUPER_ADMIN,
        description: 'The almighty user of the platform. This role can be granted only by the platform administrator.'
    },
    {
        _id: '5e228978ab559e56783edbbb',
        name: rolesNames.ADMIN,
        description: 'This user is able to manage client accounts.'
    },
    {
        _id: '5e228978ab559e56783edccc',
        name: rolesNames.CLIENT_OWNER,
        description: 'This user is able to manage all stuff related to his/her company.'
    },
    {
        _id: '5e228978ab559e56783edddd',
        name: rolesNames.CLIENT_MEMBER,
        description: 'This user is able to manage projects from his/her company.'
    }
];
