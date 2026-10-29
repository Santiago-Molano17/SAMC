const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const env = require("../../config/env");
const db = require("../../config/database");
const { badRequest, notFound } = require("../../utils/errors");
const { hashPassword } = require("../auth/auth.service");

const AVATAR_DIR = path.join(env.storageDir, "avatars");

// Se identifica el tipo real por sus primeros bytes, no por la extensión ni el mimetype del cliente
const IMAGE_SIGNATURES = [
    { ext: "png", mime: "image/png", test: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
    { ext: "jpg", mime: "image/jpeg", test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
    { ext: "gif", mime: "image/gif", test: (b) => b.subarray(0, 4).toString("ascii") === "GIF8" },
    { ext: "webp", mime: "image/webp", test: (b) => b.subarray(0, 4).toString("ascii") === "RIFF" && b.subarray(8, 12).toString("ascii") === "WEBP" }
];

const MIME_BY_EXT = Object.fromEntries(IMAGE_SIGNATURES.map((s) => [s.ext, s.mime]));

async function getProfile(userId) {
    const row = await db.queryOne(
        `SELECT u.id, u.full_name, u.email, u.created_at, u.last_login_at, u.password_changed_at,
                r.code AS role, r.name AS role_name,
                p.job_title, p.department, p.phone, p.location, p.bio, p.avatar_file, p.updated_at
         FROM users u
         INNER JOIN roles r ON r.id = u.role_id
         LEFT JOIN user_profiles p ON p.user_id = u.id
         WHERE u.id = ?`,
        [userId]
    );
    if (!row) throw notFound("Usuario no encontrado");

    const [stats] = await db.query(
        `SELECT COUNT(*) AS total,
                SUM(verdict = 'malicious') AS malicious,
                SUM(verdict = 'suspicious') AS suspicious,
                SUM(verdict = 'clean') AS clean
         FROM analyses WHERE submitted_by = ?`,
        [userId]
    );
    const [reviews] = await db.query("SELECT COUNT(*) AS total FROM analysis_reviews WHERE analyst_id = ?", [userId]);

    return {
        id: row.id,
        fullName: row.full_name,
        email: row.email,
        role: row.role,
        roleName: row.role_name,
        jobTitle: row.job_title,
        department: row.department,
        phone: row.phone,
        location: row.location,
        bio: row.bio,
        avatarUrl: row.avatar_file ? `/api/users/${row.id}/avatar?v=${new Date(row.updated_at).getTime()}` : null,
        createdAt: row.created_at,
        lastLoginAt: row.last_login_at,
        passwordChangedAt: row.password_changed_at,
        stats: {
            analyses: Number(stats.total) || 0,
            malicious: Number(stats.malicious) || 0,
            suspicious: Number(stats.suspicious) || 0,
            clean: Number(stats.clean) || 0,
            reviews: Number(reviews.total) || 0
        }
    };
}

async function updateProfile(userId, data) {
    await db.transaction(async (tx) => {
        if (data.fullName) {
            await tx.query("UPDATE users SET full_name = ? WHERE id = ?", [data.fullName, userId]);
        }
        await tx.query(
            `INSERT INTO user_profiles (user_id, job_title, department, phone, location, bio)
             VALUES (?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE job_title = VALUES(job_title), department = VALUES(department),
                phone = VALUES(phone), location = VALUES(location), bio = VALUES(bio)`,
            [userId, data.jobTitle || null, data.department || null, data.phone || null, data.location || null, data.bio || null]
        );
    });
    return getProfile(userId);
}

async function changePassword(userId, currentPassword, newPassword) {
    const user = await db.queryOne("SELECT password_hash FROM users WHERE id = ?", [userId]);
    if (!user || !(await bcrypt.compare(currentPassword, user.password_hash))) {
        throw badRequest("La contraseña actual no es correcta", { currentPassword: "La contraseña actual no es correcta" });
    }
    if (await bcrypt.compare(newPassword, user.password_hash)) {
        throw badRequest("La nueva contraseña debe ser distinta", { newPassword: "Debe ser distinta a la actual" });
    }
    await db.query(
        "UPDATE users SET password_hash = ?, password_changed_at = UTC_TIMESTAMP() WHERE id = ?",
        [await hashPassword(newPassword), userId]
    );
}

async function setAvatar(userId, file) {
    if (!file) throw badRequest("Selecciona una imagen");

    const signature = IMAGE_SIGNATURES.find((s) => s.test(file.buffer));
    if (!signature) throw badRequest("La foto debe ser PNG, JPG, GIF o WEBP");

    await fs.mkdir(AVATAR_DIR, { recursive: true });
    const fileName = `${userId}-${crypto.randomBytes(6).toString("hex")}.${signature.ext}`;
    await fs.writeFile(path.join(AVATAR_DIR, fileName), file.buffer);

    const previous = await db.queryOne("SELECT avatar_file FROM user_profiles WHERE user_id = ?", [userId]);
    await db.query(
        `INSERT INTO user_profiles (user_id, avatar_file) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE avatar_file = VALUES(avatar_file)`,
        [userId, fileName]
    );
    await removeAvatarFile(previous?.avatar_file);
}

async function removeAvatar(userId) {
    const previous = await db.queryOne("SELECT avatar_file FROM user_profiles WHERE user_id = ?", [userId]);
    await db.query("UPDATE user_profiles SET avatar_file = NULL WHERE user_id = ?", [userId]);
    await removeAvatarFile(previous?.avatar_file);
}

async function removeAvatarFile(fileName) {
    if (!fileName) return;
    await fs.unlink(path.join(AVATAR_DIR, path.basename(fileName))).catch(() => {});
}

async function getAvatarFile(userId) {
    const row = await db.queryOne("SELECT avatar_file FROM user_profiles WHERE user_id = ?", [userId]);
    if (!row?.avatar_file) throw notFound("Sin foto de perfil");
    const fileName = path.basename(row.avatar_file);
    const ext = path.extname(fileName).slice(1);
    return { filePath: path.join(AVATAR_DIR, fileName), mime: MIME_BY_EXT[ext] || "application/octet-stream" };
}

module.exports = { getProfile, updateProfile, changePassword, setAvatar, removeAvatar, getAvatarFile };
