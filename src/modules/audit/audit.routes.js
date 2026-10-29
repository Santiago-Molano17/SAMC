const express = require("express");
const { z } = require("zod");
const db = require("../../config/database");
const { authenticate, requireRole } = require("../../middleware/auth");
const { validate } = require("../../middleware/validate");
const { ROLES } = require("../../utils/roles");
const { paginate, pageResult } = require("../../utils/pagination");

const router = express.Router();
router.use(authenticate, requireRole(ROLES.ADMIN));

const listSchema = z.object({
    q: z.string().trim().max(100).optional(),
    action: z.string().trim().max(60).optional(),
    from: z.coerce.date().optional(),
    to: z.coerce.date().optional()
});

router.get("/", validate(listSchema, "query"), async (req, res) => {
    const { q, action, from, to } = req.valid.query;
    const page = paginate(req.query);
    const where = [];
    const params = [];

    if (q) {
        where.push("(u.email LIKE ? OR u.full_name LIKE ? OR l.ip_address LIKE ? OR l.entity_id = ?)");
        params.push(`%${q}%`, `%${q}%`, `%${q}%`, q);
    }
    if (action) {
        where.push("l.action LIKE ?");
        params.push(`${action}%`);
    }
    if (from) {
        where.push("l.created_at >= ?");
        params.push(from);
    }
    if (to) {
        where.push("l.created_at <= ?");
        params.push(to);
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const from_ = `FROM audit_logs l LEFT JOIN users u ON u.id = l.user_id ${whereSql}`;

    const [{ total }] = await db.query(`SELECT COUNT(*) AS total ${from_}`, params);
    const rows = await db.query(
        `SELECT l.id, l.action, l.entity_type, l.entity_id, l.ip_address, l.user_agent, l.metadata, l.created_at,
                u.full_name, u.email
         ${from_} ORDER BY l.created_at DESC, l.id DESC LIMIT ? OFFSET ?`,
        [...params, page.limit, page.offset]
    );

    const actions = await db.query(
        "SELECT action, COUNT(*) AS total FROM audit_logs WHERE created_at >= UTC_TIMESTAMP() - INTERVAL 30 DAY GROUP BY action ORDER BY total DESC"
    );

    res.json({
        ...pageResult(rows.map((r) => ({
            id: r.id,
            action: r.action,
            entityType: r.entity_type,
            entityId: r.entity_id,
            ip: r.ip_address,
            userAgent: r.user_agent,
            metadata: r.metadata,
            createdAt: r.created_at,
            user: r.email ? { fullName: r.full_name, email: r.email } : null
        })), Number(total), page),
        actions: actions.map((a) => ({ action: a.action, total: Number(a.total) }))
    });
});

module.exports = router;
