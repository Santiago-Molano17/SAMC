const db = require("../../config/database");
const { badRequest, forbidden, notFound } = require("../../utils/errors");
const { ROLE_IDS, ROLES, canManage } = require("../../utils/roles");
const { pageResult } = require("../../utils/pagination");
const { avatarUrl, createUser } = require("../auth/auth.service");

const USER_COLUMNS = `
    u.id, u.full_name, u.email, u.status, u.last_login_at, u.created_at, u.locked_until,
    r.code AS role, r.name AS role_name,
    p.job_title, p.department, p.avatar_file, p.updated_at AS profile_updated_at,
    (SELECT COUNT(*) FROM analyses a WHERE a.submitted_by = u.id) AS analyses_count`;

function toUser(row) {
    return {
        id: row.id,
        fullName: row.full_name,
        email: row.email,
        status: row.status,
        role: row.role,
        roleName: row.role_name,
        jobTitle: row.job_title,
        department: row.department,
        avatarUrl: avatarUrl(row.id, row.avatar_file, row.profile_updated_at),
        analysesCount: Number(row.analyses_count) || 0,
        locked: Boolean(row.locked_until && new Date(row.locked_until) > new Date()),
        lastLoginAt: row.last_login_at,
        createdAt: row.created_at
    };
}

async function listUsers({ q, role, status }, page) {
    const where = [];
    const params = [];

    if (q) {
        where.push("(u.full_name LIKE ? OR u.email LIKE ?)");
        params.push(`%${q}%`, `%${q}%`);
    }
    if (role) {
        where.push("r.code = ?");
        params.push(role);
    }
    if (status) {
        where.push("u.status = ?");
        params.push(status);
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const from = `FROM users u INNER JOIN roles r ON r.id = u.role_id LEFT JOIN user_profiles p ON p.user_id = u.id ${whereSql}`;

    const [{ total }] = await db.query(`SELECT COUNT(*) AS total ${from}`, params);
    const rows = await db.query(
        `SELECT ${USER_COLUMNS} ${from} ORDER BY r.level DESC, u.full_name ASC LIMIT ? OFFSET ?`,
        [...params, page.limit, page.offset]
    );

    const [counts] = await db.query(
        `SELECT COUNT(*) AS total, SUM(u.status = 'active') AS active, SUM(u.status = 'suspended') AS suspended,
                SUM(r.code IN ('ADMIN','SUPER_ADMIN')) AS admins, SUM(r.code = 'ANALYST') AS analysts
         FROM users u INNER JOIN roles r ON r.id = u.role_id`
    );

    return {
        ...pageResult(rows.map(toUser), Number(total), page),
        summary: {
            total: Number(counts.total) || 0,
            active: Number(counts.active) || 0,
            suspended: Number(counts.suspended) || 0,
            admins: Number(counts.admins) || 0,
            analysts: Number(counts.analysts) || 0
        }
    };
}

async function getTarget(id) {
    const row = await db.queryOne(
        `SELECT ${USER_COLUMNS} FROM users u INNER JOIN roles r ON r.id = u.role_id
         LEFT JOIN user_profiles p ON p.user_id = u.id WHERE u.id = ?`,
        [id]
    );
    if (!row) throw notFound("Usuario no encontrado");
    return toUser(row);
}

async function countSuperAdmins() {
    const [{ total }] = await db.query(
        "SELECT COUNT(*) AS total FROM users WHERE role_id = ? AND status = 'active'",
        [ROLE_IDS.SUPER_ADMIN]
    );
    return Number(total);
}

function assertCanManage(actor, target, newRole) {
    if (actor.id === target.id) {
        throw forbidden("No puedes modificar tu propia cuenta desde aquí. Usa tu perfil");
    }
    if (!canManage(actor.role, target.role)) {
        throw forbidden("No puedes gestionar usuarios con este rol");
    }
    if (newRole && !canManage(actor.role, newRole)) {
        throw forbidden("No puedes asignar ese rol");
    }
}

async function create(actor, data) {
    if (!canManage(actor.role, data.role)) throw forbidden("No puedes crear usuarios con ese rol");
    const id = await createUser({
        fullName: data.fullName,
        email: data.email,
        password: data.password,
        roleId: ROLE_IDS[data.role],
        profile: { jobTitle: data.jobTitle, department: data.department }
    });
    return getTarget(id);
}

async function update(actor, id, data) {
    const target = await getTarget(id);
    assertCanManage(actor, target, data.role);

    const losesSuperAdmin = target.role === ROLES.SUPER_ADMIN &&
        ((data.role && data.role !== ROLES.SUPER_ADMIN) || data.status === "suspended");
    if (losesSuperAdmin && (await countSuperAdmins()) <= 1) {
        throw badRequest("Debe existir al menos un super administrador activo");
    }

    const sets = [];
    const params = [];
    if (data.fullName) {
        sets.push("full_name = ?");
        params.push(data.fullName);
    }
    if (data.role) {
        sets.push("role_id = ?");
        params.push(ROLE_IDS[data.role]);
    }
    if (data.status) {
        sets.push("status = ?");
        params.push(data.status);
    }
    if (data.unlock) {
        sets.push("locked_until = NULL", "failed_login_attempts = 0");
    }

    if (sets.length) {
        await db.query(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`, [...params, id]);
    }

    return { before: target, after: await getTarget(id) };
}

async function remove(actor, id) {
    const target = await getTarget(id);
    assertCanManage(actor, target);

    if (target.role === ROLES.SUPER_ADMIN && (await countSuperAdmins()) <= 1) {
        throw badRequest("Debe existir al menos un super administrador activo");
    }

    // Los análisis, revisiones y casos se conservan (las llaves quedan en NULL)
    await db.query("DELETE FROM users WHERE id = ?", [id]);
    return target;
}

async function listStaff() {
    const rows = await db.query(
        `SELECT u.id, u.full_name, r.code AS role, p.avatar_file, p.updated_at AS profile_updated_at
         FROM users u INNER JOIN roles r ON r.id = u.role_id LEFT JOIN user_profiles p ON p.user_id = u.id
         WHERE r.level >= 2 AND u.status = 'active' ORDER BY u.full_name`
    );
    return rows.map((r) => ({ id: r.id, fullName: r.full_name, role: r.role, avatarUrl: avatarUrl(r.id, r.avatar_file, r.profile_updated_at) }));
}

module.exports = { listUsers, getTarget, create, update, remove, listStaff };
