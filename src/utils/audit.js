const db = require("../config/database");

/**
 * Registra una acción en la auditoría. Nunca lanza: un fallo de auditoría
 * no debe romper la operación del usuario.
 */
async function audit(req, action, { entityType = null, entityId = null, metadata = null, userId } = {}) {
    try {
        await db.query(
            `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, ip_address, user_agent, metadata)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                userId !== undefined ? userId : req?.user?.id || null,
                action,
                entityType,
                entityId ? String(entityId) : null,
                req?.ip || null,
                req?.get?.("user-agent")?.slice(0, 255) || null,
                metadata ? JSON.stringify(metadata) : null
            ]
        );
    } catch (error) {
        console.error("No se pudo registrar auditoría:", error.message);
    }
}

module.exports = { audit };
