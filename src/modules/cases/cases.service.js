const crypto = require("crypto");
const db = require("../../config/database");
const { badRequest, notFound } = require("../../utils/errors");
const { pageResult } = require("../../utils/pagination");
const { avatarUrl } = require("../auth/auth.service");

const person = (id, name, file, version) => (id ? { id, fullName: name, avatarUrl: avatarUrl(id, file, version) } : null);

const CASE_SELECT = `
    SELECT c.*, cu.full_name AS creator_name, cp.avatar_file AS creator_avatar, cp.updated_at AS creator_v,
           au.full_name AS assignee_name, ap.avatar_file AS assignee_avatar, ap.updated_at AS assignee_v,
           (SELECT COUNT(*) FROM case_analyses ca WHERE ca.case_id = c.id) AS analyses_count,
           (SELECT COUNT(*) FROM case_notes cn WHERE cn.case_id = c.id) AS notes_count,
           (SELECT MAX(a.risk_score) FROM case_analyses ca INNER JOIN analyses a ON a.id = ca.analysis_id WHERE ca.case_id = c.id) AS max_risk
    FROM cases c
    LEFT JOIN users cu ON cu.id = c.created_by LEFT JOIN user_profiles cp ON cp.user_id = cu.id
    LEFT JOIN users au ON au.id = c.assigned_to LEFT JOIN user_profiles ap ON ap.user_id = au.id`;

function toCase(row) {
    return {
        id: row.id,
        code: row.code,
        title: row.title,
        description: row.description,
        status: row.status,
        priority: row.priority,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        closedAt: row.closed_at,
        createdBy: person(row.created_by, row.creator_name, row.creator_avatar, row.creator_v),
        assignedTo: person(row.assigned_to, row.assignee_name, row.assignee_avatar, row.assignee_v),
        analysesCount: Number(row.analyses_count) || 0,
        notesCount: Number(row.notes_count) || 0,
        maxRisk: row.max_risk === null ? null : Number(row.max_risk)
    };
}

async function nextCode(tx) {
    const year = new Date().getUTCFullYear();
    const [row] = await tx.query("SELECT COUNT(*) AS total FROM cases WHERE code LIKE ? FOR UPDATE", [`CASE-${year}-%`]);
    return `CASE-${year}-${String(Number(row.total) + 1).padStart(4, "0")}`;
}

async function assertStaff(userId) {
    if (!userId) return;
    const row = await db.queryOne(
        "SELECT u.id FROM users u INNER JOIN roles r ON r.id = u.role_id WHERE u.id = ? AND r.level >= 2 AND u.status = 'active'",
        [userId]
    );
    if (!row) throw badRequest("El responsable debe ser un analista o administrador activo", { assignedTo: "Responsable inválido" });
}

async function list({ q, status, priority, mine }, page, user) {
    const where = [];
    const params = [];
    if (q) {
        where.push("(c.title LIKE ? OR c.code LIKE ? OR c.description LIKE ?)");
        params.push(`%${q}%`, `%${q}%`, `%${q}%`);
    }
    if (status === "active") where.push("c.status <> 'closed'");
    else if (status) {
        where.push("c.status = ?");
        params.push(status);
    }
    if (priority) {
        where.push("c.priority = ?");
        params.push(priority);
    }
    if (mine) {
        where.push("c.assigned_to = ?");
        params.push(user.id);
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [{ total }] = await db.query(`SELECT COUNT(*) AS total FROM cases c ${whereSql}`, params);
    const rows = await db.query(
        `${CASE_SELECT} ${whereSql}
         ORDER BY FIELD(c.status, 'investigating', 'open', 'contained', 'closed'), FIELD(c.priority, 'critical', 'high', 'medium', 'low'), c.updated_at DESC
         LIMIT ? OFFSET ?`,
        [...params, page.limit, page.offset]
    );
    const [counts] = await db.query(
        `SELECT SUM(status = 'open') AS open, SUM(status = 'investigating') AS investigating,
                SUM(status = 'contained') AS contained, SUM(status = 'closed') AS closed,
                SUM(status <> 'closed' AND priority IN ('high', 'critical')) AS urgent
         FROM cases`
    );
    return {
        ...pageResult(rows.map(toCase), Number(total), page),
        counts: Object.fromEntries(Object.entries(counts).map(([k, v]) => [k, Number(v) || 0]))
    };
}

async function get(id) {
    const row = await db.queryOne(`${CASE_SELECT} WHERE c.id = ?`, [id]);
    if (!row) throw notFound("Caso no encontrado");

    const [analyses, notes] = await Promise.all([
        db.query(
            `SELECT a.id, a.original_name, a.verdict, a.reviewed_verdict, a.risk_score, a.threat_family, a.submitted_at,
                    s.sha256, ca.added_at, u.full_name AS added_by
             FROM case_analyses ca INNER JOIN analyses a ON a.id = ca.analysis_id INNER JOIN samples s ON s.id = a.sample_id
             LEFT JOIN users u ON u.id = ca.added_by
             WHERE ca.case_id = ? ORDER BY a.risk_score DESC`,
            [id]
        ),
        db.query(
            `SELECT n.id, n.body, n.created_at, u.id AS author_id, u.full_name, p.avatar_file, p.updated_at AS avatar_v
             FROM case_notes n LEFT JOIN users u ON u.id = n.author_id LEFT JOIN user_profiles p ON p.user_id = u.id
             WHERE n.case_id = ? ORDER BY n.created_at DESC, n.id DESC`,
            [id]
        )
    ]);

    return {
        ...toCase(row),
        analyses: analyses.map((a) => ({
            id: a.id,
            originalName: a.original_name,
            finalVerdict: a.reviewed_verdict || a.verdict,
            riskScore: a.risk_score,
            threatFamily: a.threat_family,
            sha256: a.sha256,
            submittedAt: a.submitted_at,
            addedAt: a.added_at,
            addedBy: a.added_by
        })),
        notes: notes.map((n) => ({
            id: n.id,
            body: n.body,
            createdAt: n.created_at,
            author: person(n.author_id, n.full_name, n.avatar_file, n.avatar_v)
        }))
    };
}

async function create(user, data) {
    await assertStaff(data.assignedTo);
    const id = crypto.randomUUID();

    await db.transaction(async (tx) => {
        const code = await nextCode(tx);
        await tx.query(
            "INSERT INTO cases (id, code, title, description, priority, created_by, assigned_to) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [id, code, data.title, data.description || null, data.priority, user.id, data.assignedTo || user.id]
        );
        for (const analysisId of data.analysisIds || []) {
            await tx.query("INSERT IGNORE INTO case_analyses (case_id, analysis_id, added_by) SELECT ?, id, ? FROM analyses WHERE id = ?", [id, user.id, analysisId]);
        }
        await tx.query("INSERT INTO case_notes (case_id, author_id, body) VALUES (?, ?, ?)", [id, user.id, `Caso abierto con prioridad ${data.priority}.`]);
    });

    return get(id);
}

const STATUS_LABEL = { open: "Abierto", investigating: "En investigación", contained: "Contenido", closed: "Cerrado" };

async function update(user, id, data) {
    const current = await get(id);
    if (data.assignedTo !== undefined) await assertStaff(data.assignedTo);

    const sets = [];
    const params = [];
    for (const [field, column] of [["title", "title"], ["description", "description"], ["priority", "priority"], ["assignedTo", "assigned_to"]]) {
        if (data[field] !== undefined) {
            sets.push(`${column} = ?`);
            params.push(data[field] || null);
        }
    }
    if (data.status) {
        sets.push("status = ?", "closed_at = ?");
        params.push(data.status, data.status === "closed" ? new Date() : null);
    }
    if (sets.length) await db.query(`UPDATE cases SET ${sets.join(", ")} WHERE id = ?`, [...params, id]);

    if (data.status && data.status !== current.status) {
        await db.query("INSERT INTO case_notes (case_id, author_id, body) VALUES (?, ?, ?)", [
            id, user.id, `Estado cambiado de "${STATUS_LABEL[current.status]}" a "${STATUS_LABEL[data.status]}".`
        ]);
    }
    return get(id);
}

async function addNote(user, id, body) {
    await get(id);
    await db.query("INSERT INTO case_notes (case_id, author_id, body) VALUES (?, ?, ?)", [id, user.id, body]);
    await db.query("UPDATE cases SET updated_at = UTC_TIMESTAMP() WHERE id = ?", [id]);
    return get(id);
}

async function linkAnalysis(user, id, analysisId) {
    await get(id);
    const analysis = await db.queryOne("SELECT id FROM analyses WHERE id = ?", [analysisId]);
    if (!analysis) throw notFound("Análisis no encontrado");
    await db.query("INSERT IGNORE INTO case_analyses (case_id, analysis_id, added_by) VALUES (?, ?, ?)", [id, analysisId, user.id]);
    await db.query("UPDATE cases SET updated_at = UTC_TIMESTAMP() WHERE id = ?", [id]);
    return get(id);
}

async function unlinkAnalysis(id, analysisId) {
    await get(id);
    await db.query("DELETE FROM case_analyses WHERE case_id = ? AND analysis_id = ?", [id, analysisId]);
    return get(id);
}

module.exports = { list, get, create, update, addNote, linkAnalysis, unlinkAnalysis };
