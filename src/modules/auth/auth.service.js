const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const db = require("../../config/database");
const { unauthorized, conflict, AppError } = require("../../utils/errors");
const { ROLE_IDS } = require("../../utils/roles");

const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

// Hash ficticio: se compara aunque el correo no exista para que el tiempo de
// respuesta no revele qué cuentas están registradas
const DUMMY_HASH = bcrypt.hashSync("sacm-dummy-password", BCRYPT_ROUNDS);

const hashPassword = (plain) => bcrypt.hash(plain, BCRYPT_ROUNDS);

async function createUser({ fullName, email, password, roleId = ROLE_IDS.USER, profile = {} }) {
    const existing = await db.queryOne("SELECT id FROM users WHERE email = ?", [email]);
    if (existing) throw conflict("El correo ya está registrado");

    const id = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    await db.transaction(async (tx) => {
        await tx.query(
            "INSERT INTO users (id, role_id, full_name, email, password_hash, password_changed_at) VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP())",
            [id, roleId, fullName, email, passwordHash]
        );
        await tx.query(
            "INSERT INTO user_profiles (user_id, job_title, department) VALUES (?, ?, ?)",
            [id, profile.jobTitle || null, profile.department || null]
        );
    });

    return id;
}

async function login(email, password) {
    const user = await db.queryOne(
        `SELECT u.id, u.full_name, u.email, u.password_hash, u.status, u.failed_login_attempts,
                u.locked_until, r.code AS role
         FROM users u INNER JOIN roles r ON r.id = u.role_id
         WHERE u.email = ?`,
        [email]
    );

    if (!user) {
        await bcrypt.compare(password, DUMMY_HASH);
        throw unauthorized("Correo o contraseña incorrectos");
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
        const minutes = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
        throw new AppError(423, `Cuenta bloqueada por intentos fallidos. Intenta en ${minutes} min`);
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
        const attempts = user.failed_login_attempts + 1;
        const lock = attempts >= MAX_FAILED_ATTEMPTS;
        await db.query(
            `UPDATE users SET failed_login_attempts = ?,
                locked_until = IF(?, UTC_TIMESTAMP() + INTERVAL ${LOCK_MINUTES} MINUTE, NULL)
             WHERE id = ?`,
            [lock ? 0 : attempts, lock, user.id]
        );
        const error = unauthorized(lock
            ? `Demasiados intentos. Cuenta bloqueada ${LOCK_MINUTES} minutos`
            : "Correo o contraseña incorrectos");
        error.userId = user.id;
        throw error;
    }

    if (user.status !== "active") {
        throw new AppError(403, "Tu cuenta está suspendida. Contacta a un administrador");
    }

    await db.query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = UTC_TIMESTAMP() WHERE id = ?",
        [user.id]
    );

    return { id: user.id, fullName: user.full_name, email: user.email, role: user.role };
}

async function getSessionUser(userId) {
    const row = await db.queryOne(
        `SELECT u.id, u.full_name, u.email, u.last_login_at, u.created_at,
                r.code AS role, r.name AS role_name,
                p.job_title, p.department, p.avatar_file, p.updated_at AS profile_updated_at
         FROM users u
         INNER JOIN roles r ON r.id = u.role_id
         LEFT JOIN user_profiles p ON p.user_id = u.id
         WHERE u.id = ?`,
        [userId]
    );
    return row ? toSessionUser(row) : null;
}

function avatarUrl(userId, avatarFile, version) {
    if (!avatarFile) return null;
    const v = version ? new Date(version).getTime() : Date.now();
    return `/api/users/${userId}/avatar?v=${v}`;
}

function toSessionUser(row) {
    return {
        id: row.id,
        fullName: row.full_name,
        email: row.email,
        role: row.role,
        roleName: row.role_name,
        jobTitle: row.job_title,
        department: row.department,
        avatarUrl: avatarUrl(row.id, row.avatar_file, row.profile_updated_at),
        lastLoginAt: row.last_login_at,
        createdAt: row.created_at
    };
}

module.exports = { hashPassword, createUser, login, getSessionUser, avatarUrl, BCRYPT_ROUNDS };
