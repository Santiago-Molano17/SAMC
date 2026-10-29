const ROLES = Object.freeze({
    SUPER_ADMIN: "SUPER_ADMIN",
    ADMIN: "ADMIN",
    ANALYST: "ANALYST",
    USER: "USER"
});

const ROLE_LEVEL = Object.freeze({
    SUPER_ADMIN: 4,
    ADMIN: 3,
    ANALYST: 2,
    USER: 1
});

const ROLE_IDS = Object.freeze({
    SUPER_ADMIN: 1,
    ADMIN: 2,
    ANALYST: 3,
    USER: 4
});

/** ¿El rol tiene al menos el nivel de `minimum`? */
const hasLevel = (role, minimum) => (ROLE_LEVEL[role] || 0) >= ROLE_LEVEL[minimum];

/** Un ADMIN gestiona USER y ANALYST; el SUPER_ADMIN gestiona a todos */
function canManage(actorRole, targetRole) {
    if (actorRole === ROLES.SUPER_ADMIN) return true;
    if (actorRole === ROLES.ADMIN) return [ROLES.USER, ROLES.ANALYST].includes(targetRole);
    return false;
}

module.exports = { ROLES, ROLE_LEVEL, ROLE_IDS, hasLevel, canManage };
