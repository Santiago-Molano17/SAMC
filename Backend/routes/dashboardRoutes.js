const express = require("express");

const router = express.Router();

const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const db = require("../db");

const { verifyToken, verifyRole, ROLES } = require("../middleware/authMiddleware");

const dbp = db.promise();

async function ensureAnalysisSchema() {
    const ignoredErrors = new Set(["ER_DUP_FIELDNAME", "ER_DUP_KEYNAME", "ER_FK_DUP_NAME", "ER_CANT_CREATE_TABLE"]);
    const migrations = [
        "ALTER TABLE analysis ADD COLUMN risk_percentage INT DEFAULT 0",
        "ALTER TABLE analysis ADD COLUMN affected_system_areas JSON NULL",
        "ALTER TABLE analysis ADD COLUMN detected_capabilities JSON NULL",
        "ALTER TABLE analysis ADD COLUMN recommendation TEXT NULL",
        "ALTER TABLE analysis ADD COLUMN analyzed_by VARCHAR(36) NULL"
    ];

    for (const sql of migrations) {
        try {
            await dbp.query(sql);
        } catch (err) {
            if (!ignoredErrors.has(err.code)) {
                throw err;
            }
        }
    }
}

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || "");
}

function validatePassword(password) {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(password || "");
}

async function writeLog(userId, actionType, resourceType, resourceId, details) {
    try {
        await dbp.query(
            "INSERT INTO activity_logs (user_id, action_type, resource_type, resource_id, details) VALUES (?, ?, ?, ?, ?)",
            [userId, actionType, resourceType, resourceId, JSON.stringify(details || {})]
        );
    } catch (error) {
        console.error("No se pudo registrar log:", error.message);
    }
}

// =========================
// DASHBOARD STATS (ADMIN)
// =========================

router.get("/stats", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), async (req, res) => {
    try {
        await ensureAnalysisSchema();

        const [[usersCount], [analysisCount], [criticalCount], [highCount], [recentAnalysis], [malwareStats], [riskStats]] =
            await Promise.all([
                dbp.query("SELECT COUNT(*) AS totalUsers FROM users"),
                dbp.query("SELECT COUNT(*) AS totalAnalysis FROM analysis"),
                dbp.query("SELECT COUNT(*) AS criticalRisk FROM analysis WHERE risk_level = 'Critical'"),
                dbp.query("SELECT COUNT(*) AS highRisk FROM analysis WHERE risk_level = 'High'"),
                dbp.query(`
                    SELECT
                        a.id,
                        a.malware_type,
                        a.risk_level,
                        a.risk_percentage,
                        a.analysis_date,
                        u.original_name,
                        u.file_size,
                        user.email AS user_email,
                        user.fullname
                    FROM analysis a
                    INNER JOIN uploads u ON a.upload_id = u.id
                    INNER JOIN users user ON u.user_id = user.id
                    ORDER BY a.analysis_date DESC
                    LIMIT 10
                `),
                dbp.query(`
                    SELECT COALESCE(malware_type, 'Sin clasificar') AS malware_type, COUNT(*) AS count
                    FROM analysis
                    GROUP BY COALESCE(malware_type, 'Sin clasificar')
                    ORDER BY count DESC
                    LIMIT 8
                `),
                dbp.query(`
                    SELECT COALESCE(risk_level, 'Sin nivel') AS risk_level, COUNT(*) AS count
                    FROM analysis
                    GROUP BY COALESCE(risk_level, 'Sin nivel')
                `)
            ]);

        res.json({
            totalUsers: usersCount[0].totalUsers,
            totalAnalysis: analysisCount[0].totalAnalysis,
            criticalRisk: criticalCount[0].criticalRisk,
            highRisk: highCount[0].highRisk,
            recentAnalysis,
            malwareStats,
            riskStats
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// GET ALL ANALYSIS
// =========================

router.get("/all-analysis", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), async (req, res) => {
    try {
        await ensureAnalysisSchema();
        const sql = `
            SELECT
                a.id,
                a.malware_type,
                a.risk_level,
                a.risk_percentage,
                a.analysis_date,
                u.original_name,
                u.file_size,
                u.file_type,
                user.email,
                user.fullname
            FROM analysis a
            INNER JOIN uploads u ON a.upload_id = u.id
            INNER JOIN users user ON u.user_id = user.id
            ORDER BY a.analysis_date DESC
            LIMIT 100
        `;

        db.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                message: "Análisis obtenidos",
                total: results.length,
                analysis: results
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// GET ALL USERS
// =========================

router.get("/users", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), (req, res) => {
    try {
        const sql = `
            SELECT
                u.id,
                u.fullname,
                u.email,
                r.role_name,
                u.created_at
            FROM users u
            INNER JOIN roles r ON u.role_id = r.id
            ORDER BY u.created_at DESC
        `;

        db.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                message: "Usuarios obtenidos",
                total: results.length,
                users: results
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// CREATE USER
// =========================

router.post("/users", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN]), async (req, res) => {
    try {
        const { fullname, email, password, role } = req.body;

        if (!fullname || !email || !password || !role) {
            return res.status(400).json({ message: "Todos los campos son obligatorios" });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ message: "Email inválido" });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ message: "La contraseña debe tener al menos 8 caracteres, mayúsculas, minúsculas y números" });
        }

        if (!Object.values(ROLES).includes(role)) {
            return res.status(400).json({ message: "Rol inválido" });
        }

        if (req.user.role !== ROLES.SUPER_ADMIN && [ROLES.SUPER_ADMIN, ROLES.ADMIN].includes(role)) {
            return res.status(403).json({ message: "No tienes permiso para crear administradores" });
        }

        const [existing] = await dbp.query("SELECT id FROM users WHERE email = ?", [email.trim().toLowerCase()]);
        if (existing.length > 0) {
            return res.status(400).json({ message: "El correo ya está registrado" });
        }

        const [roles] = await dbp.query("SELECT id FROM roles WHERE role_name = ?", [role]);
        if (roles.length === 0) {
            return res.status(400).json({ message: "Rol no encontrado" });
        }

        const userId = uuidv4();
        const hashedPassword = await bcrypt.hash(password, 12);

        await dbp.query(
            "INSERT INTO users (id, fullname, email, password, role_id) VALUES (?, ?, ?, ?, ?)",
            [userId, fullname.trim(), email.trim().toLowerCase(), hashedPassword, roles[0].id]
        );

        await dbp.query(
            "INSERT INTO user_profiles (id, user_id, department, profile_status) VALUES (?, ?, ?, 'ACTIVE')",
            [uuidv4(), userId, "General"]
        );

        await writeLog(req.user.id, "CREATE_USER", "users", userId, { email, role });

        res.status(201).json({ message: "Usuario creado correctamente" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// GET USER PROFILES
// =========================

router.get("/profiles", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), (req, res) => {
    try {
        const sql = `
            SELECT
                up.id,
                u.id AS user_id,
                COALESCE(up.department, 'General') AS department,
                COALESCE(up.profile_status, 'ACTIVE') AS profile_status,
                up.last_login,
                u.fullname,
                u.email,
                r.role_name
            FROM users u
            LEFT JOIN user_profiles up ON up.user_id = u.id
            INNER JOIN roles r ON u.role_id = r.id
            ORDER BY COALESCE(up.profile_created_at, u.created_at) DESC
        `;

        db.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                message: "Perfiles obtenidos",
                total: results.length,
                profiles: results
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// GET ACTIVITY LOGS
// =========================

router.get("/logs", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), (req, res) => {
    try {
        const activitySql = `
            SELECT
                l.id,
                l.user_id,
                l.action_type,
                CAST(l.details AS CHAR) AS action_details,
                l.action_timestamp AS action_date,
                u.email AS user_email
            FROM activity_logs l
            LEFT JOIN users u ON l.user_id = u.id
            ORDER BY l.action_timestamp DESC
            LIMIT 100
        `;

        db.query(activitySql, (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (results.length > 0) {
                return res.json({
                    message: "Logs obtenidos",
                    total: results.length,
                    logs: results
                });
            }

            const analysisSql = `
                SELECT
                    a.id,
                    up.user_id,
                    'ANALYSIS_CREATED' AS action_type,
                    JSON_OBJECT(
                        'file', up.original_name,
                        'malware_type', a.malware_type,
                        'risk_level', a.risk_level,
                        'risk_percentage', a.risk_percentage
                    ) AS action_details,
                    a.analysis_date AS action_date,
                    u.email AS user_email
                FROM analysis a
                INNER JOIN uploads up ON a.upload_id = up.id
                LEFT JOIN users u ON up.user_id = u.id
                ORDER BY a.analysis_date DESC
                LIMIT 100
            `;

            db.query(analysisSql, (analysisErr, analysisResults) => {
                if (analysisErr) {
                    return res.status(500).json({ error: analysisErr.message });
                }

                res.json({
                    message: "Logs obtenidos",
                    total: analysisResults.length,
                    logs: analysisResults
                });
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// REPORT SUMMARY
// =========================

router.get("/reports/summary", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), async (req, res) => {
    try {
        await ensureAnalysisSchema();

        const [[totals], [riskLevels], [malwareTypes], [topUsers], [recentLogs]] = await Promise.all([
            dbp.query(`
                SELECT
                    COUNT(*) AS total_analysis,
                    AVG(risk_percentage) AS avg_risk,
                    SUM(CASE WHEN risk_level IN ('Critical', 'High') THEN 1 ELSE 0 END) AS dangerous_analysis
                FROM analysis
            `),
            dbp.query(`
                SELECT COALESCE(risk_level, 'Sin nivel') AS risk_level, COUNT(*) AS count
                FROM analysis
                GROUP BY COALESCE(risk_level, 'Sin nivel')
                ORDER BY count DESC
            `),
            dbp.query(`
                SELECT COALESCE(malware_type, 'Sin clasificar') AS malware_type, COUNT(*) AS count, AVG(risk_percentage) AS avg_risk
                FROM analysis
                GROUP BY COALESCE(malware_type, 'Sin clasificar')
                ORDER BY count DESC
                LIMIT 5
            `),
            dbp.query(`
                SELECT user.fullname, user.email, COUNT(*) AS total
                FROM analysis a
                INNER JOIN uploads u ON a.upload_id = u.id
                INNER JOIN users user ON u.user_id = user.id
                GROUP BY user.id, user.fullname, user.email
                ORDER BY total DESC
                LIMIT 5
            `),
            dbp.query(`
                SELECT l.action_type, l.action_timestamp AS action_date, user.email AS user_email
                FROM activity_logs l
                LEFT JOIN users user ON l.user_id = user.id
                ORDER BY l.action_timestamp DESC
                LIMIT 8
            `)
        ]);

        res.json({
            totals: totals[0],
            riskLevels,
            malwareTypes,
            topUsers,
            recentLogs
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// DELETE USER
// =========================

router.delete("/users/:userId", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN]), (req, res) => {
    try {
        const { userId } = req.params;

        if (userId === req.user.id) {
            return res.status(400).json({ message: "No puedes eliminar tu propia cuenta" });
        }

        const roleSql = "SELECT roles.role_name FROM users INNER JOIN roles ON users.role_id = roles.id WHERE users.id = ?";

        db.query(roleSql, [userId], (roleErr, rows) => {
            if (roleErr) {
                return res.status(500).json({ error: roleErr.message });
            }

            if (rows.length === 0) {
                return res.status(404).json({ message: "Usuario no encontrado" });
            }

            // Un ADMIN no puede eliminar a otros administradores
            if (req.user.role !== ROLES.SUPER_ADMIN && [ROLES.SUPER_ADMIN, ROLES.ADMIN].includes(rows[0].role_name)) {
                return res.status(403).json({ message: "Acceso denegado. Rol insuficiente" });
            }

            // Primero se eliminan o desvinculan los registros que referencian al usuario (llaves foráneas)
            const cleanup = [
                ["DELETE a FROM analysis a INNER JOIN uploads u ON a.upload_id = u.id WHERE u.user_id = ?", [userId]],
                ["DELETE FROM uploads WHERE user_id = ?", [userId]],
                ["UPDATE analysis SET analyzed_by = NULL WHERE analyzed_by = ?", [userId]],
                ["UPDATE activity_logs SET user_id = NULL WHERE user_id = ?", [userId]],
                ["UPDATE logs SET user_id = NULL WHERE user_id = ?", [userId]],
                ["DELETE FROM user_profiles WHERE user_id = ?", [userId]],
                ["DELETE FROM users WHERE id = ?", [userId]]
            ];

            cleanup
                .reduce((promise, [sql, params]) => promise.then(() => dbp.query(sql, params)), Promise.resolve())
                .then(() => {
                    writeLog(req.user.id, "DELETE_USER", "user", userId, {});
                    res.json({ message: "Usuario eliminado correctamente" });
                })
                .catch((err) => res.status(500).json({ error: err.message }));
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// UPDATE USER ROLE
// =========================

router.put("/users/:userId/role", verifyToken, verifyRole([ROLES.SUPER_ADMIN]), (req, res) => {
    try {
        const { userId } = req.params;
        const { roleId } = req.body;

        if (!roleId) {
            return res.status(400).json({ message: "Role ID requerido" });
        }

        const sql = "UPDATE users SET role_id = ? WHERE id = ?";

        db.query(sql, [roleId, userId], (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({ message: "Rol actualizado correctamente" });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// GET MALWARE DATABASE
// =========================

router.get("/malware-database", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), (req, res) => {
    try {
        const sql = `
            SELECT
                id,
                malware_name,
                malware_type,
                severity_level,
                description
            FROM malware_database
            ORDER BY malware_name
        `;

        db.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                message: "Base de datos de malware obtenida",
                total: results.length,
                malware: results
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// GET STATISTICS BY MALWARE TYPE
// =========================

router.get("/statistics/malware-types", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), (req, res) => {
    try {
        const sql = `
            SELECT
                malware_type,
                COUNT(*) as count,
                AVG(risk_percentage) as avg_risk
            FROM analysis
            GROUP BY malware_type
            ORDER BY count DESC
        `;

        db.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                message: "Estadísticas obtenidas",
                statistics: results
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// GET STATISTICS BY RISK LEVEL
// =========================

router.get("/statistics/risk-levels", verifyToken, verifyRole([ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST]), (req, res) => {
    try {
        const sql = `
            SELECT
                risk_level,
                COUNT(*) as count,
                AVG(risk_percentage) as avg_percentage
            FROM analysis
            GROUP BY risk_level
        `;

        db.query(sql, (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                message: "Estadísticas de riesgo obtenidas",
                statistics: results
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
