const db = require("../db");

// =========================
// REGISTRAR ACTIVIDAD
// =========================

exports.logActivity = (actionType, resourceType = null) => {
    return (req, res, next) => {
        try {
            const originalJson = res.json;

            res.json = function(data) {
                // Solo registrar si fue exitoso (status 2xx)
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    const userId = req.user?.id || null;
                    const details = {
                        method: req.method,
                        path: req.path,
                        timestamp: new Date()
                    };

                    const sql = `
                        INSERT INTO activity_logs 
                        (user_id, action_type, resource_type, resource_id, details)
                        VALUES (?, ?, ?, ?, ?)
                    `;

                    db.query(sql, [
                        userId,
                        actionType,
                        resourceType,
                        req.body?.id || req.params?.id || null,
                        JSON.stringify(details)
                    ], (err) => {
                        if (err) {
                            console.log("Error al registrar actividad:", err);
                        }
                    });
                }

                return originalJson.call(this, data);
            };

            next();

        } catch (error) {
            console.log("Error en middleware de logging:", error);
            next();
        }
    };
};

// =========================
// OBTENER LOGS DE ACTIVIDAD
// =========================

exports.getActivityLogs = (userId = null) => {
    return new Promise((resolve, reject) => {
        let sql = "SELECT * FROM activity_logs";
        const params = [];

        if (userId) {
            sql += " WHERE user_id = ?";
            params.push(userId);
        }

        sql += " ORDER BY action_timestamp DESC LIMIT 100";

        db.query(sql, params, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
};
