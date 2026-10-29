const crypto = require("crypto");
const path = require("path");
const db = require("../../config/database");
const { badRequest, forbidden, notFound } = require("../../utils/errors");
const { hasLevel, ROLES } = require("../../utils/roles");
const { pageResult } = require("../../utils/pagination");
const { computeHashes } = require("../../analysis/static/hashes");
const { saveSample } = require("../../analysis/storage");
const queue = require("../../analysis/queue");
const { RULES } = require("../../analysis/rules/engine");
const { PROVIDERS, LOCAL_ENGINES } = require("../../analysis/providers");
const { avatarUrl } = require("../auth/auth.service");

const ENGINE_NAMES = Object.fromEntries([...LOCAL_ENGINES, ...PROVIDERS].map((e) => [e.id, e.name]));
const RULE_INFO = Object.fromEntries(RULES.map((r) => [r.id, r]));

const isAnalyst = (user) => hasLevel(user.role, ROLES.ANALYST);

function cleanName(name) {
    // multer entrega el nombre en latin1; se recupera el UTF-8 y se quitan rutas y caracteres de control
    let decoded = name;
    try {
        decoded = Buffer.from(name, "latin1").toString("utf8");
    } catch {
        // se conserva el original
    }
    return path.basename(decoded).replace(/[\x00-\x1f\x7f]/g, "").slice(0, 255) || "archivo";
}

async function submit(user, file) {
    if (!file || !file.buffer?.length) throw badRequest("Selecciona un archivo para analizar");

    const hashes = computeHashes(file.buffer);
    const originalName = cleanName(file.originalname);

    let sample = await db.queryOne("SELECT id FROM samples WHERE sha256 = ?", [hashes.sha256]);
    if (!sample) {
        sample = { id: crypto.randomUUID() };
        await db.query(
            "INSERT INTO samples (id, sha256, sha1, md5, size_bytes, mime_type) VALUES (?, ?, ?, ?, ?, ?)",
            [sample.id, hashes.sha256, hashes.sha1, hashes.md5, file.buffer.length, null]
        );
    }

    // El antivirus del servidor podría bloquear la escritura; el primer análisis usa la copia en memoria
    await saveSample(hashes.sha256, file.buffer).catch((error) => console.warn("No se pudo guardar la muestra:", error.message));

    const id = crypto.randomUUID();
    await db.query(
        "INSERT INTO analyses (id, sample_id, submitted_by, original_name) VALUES (?, ?, ?, ?)",
        [id, sample.id, user.id, originalName]
    );

    queue.enqueue(id, file.buffer);
    return { id, sha256: hashes.sha256, originalName };
}

function buildFilters(user, query) {
    const where = [];
    const params = [];

    if (!isAnalyst(user) || query.scope === "mine") {
        where.push("a.submitted_by = ?");
        params.push(user.id);
    }
    if (query.q) {
        where.push("(a.original_name LIKE ? OR s.sha256 = ? OR s.md5 = ? OR s.sha1 = ? OR a.threat_family LIKE ?)");
        params.push(`%${query.q}%`, query.q.toLowerCase(), query.q.toLowerCase(), query.q.toLowerCase(), `%${query.q}%`);
    }
    if (query.verdict) {
        where.push("COALESCE(a.reviewed_verdict, a.verdict) = ?");
        params.push(query.verdict);
    }
    if (query.status) {
        where.push("a.status = ?");
        params.push(query.status);
    }
    if (query.from) {
        where.push("a.submitted_at >= ?");
        params.push(query.from);
    }
    if (query.to) {
        where.push("a.submitted_at <= ?");
        params.push(query.to);
    }
    if (query.needsReview) {
        where.push("a.status = 'completed' AND a.reviewed_verdict IS NULL AND (a.verdict = 'suspicious' OR (a.verdict = 'malicious' AND a.confidence < 90))");
    }
    if (query.technique) {
        where.push("EXISTS (SELECT 1 FROM analysis_techniques t WHERE t.analysis_id = a.id AND t.technique_id = ?)");
        params.push(query.technique);
    }
    if (query.family) {
        where.push("a.threat_family = ?");
        params.push(query.family);
    }

    return { whereSql: where.length ? `WHERE ${where.join(" AND ")}` : "", params };
}

const SORTS = {
    recent: "a.submitted_at DESC",
    risk: "a.risk_score DESC, a.submitted_at DESC",
    name: "a.original_name ASC"
};

function toListItem(row) {
    return {
        id: row.id,
        originalName: row.original_name,
        status: row.status,
        verdict: row.verdict,
        reviewedVerdict: row.reviewed_verdict,
        finalVerdict: row.reviewed_verdict || row.verdict,
        riskScore: row.risk_score,
        confidence: row.confidence,
        threatFamily: row.threat_family,
        threatCategory: row.threat_category,
        sha256: row.sha256,
        size: Number(row.size_bytes),
        fileType: row.detected_type,
        submittedAt: row.submitted_at,
        completedAt: row.completed_at,
        submittedBy: row.submitter_id ? { id: row.submitter_id, fullName: row.submitter_name, avatarUrl: avatarUrl(row.submitter_id, row.submitter_avatar, row.submitter_avatar_v) } : null
    };
}

const LIST_COLUMNS = `
    a.id, a.original_name, a.status, a.verdict, a.reviewed_verdict, a.risk_score, a.confidence,
    a.threat_family, a.threat_category, a.submitted_at, a.completed_at,
    s.sha256, s.size_bytes, s.detected_type,
    u.id AS submitter_id, u.full_name AS submitter_name, p.avatar_file AS submitter_avatar, p.updated_at AS submitter_avatar_v`;

const LIST_FROM = `
    FROM analyses a
    INNER JOIN samples s ON s.id = a.sample_id
    LEFT JOIN users u ON u.id = a.submitted_by
    LEFT JOIN user_profiles p ON p.user_id = u.id`;

async function list(user, query, page) {
    const { whereSql, params } = buildFilters(user, query);
    const [{ total }] = await db.query(`SELECT COUNT(*) AS total ${LIST_FROM} ${whereSql}`, params);
    const rows = await db.query(
        `SELECT ${LIST_COLUMNS} ${LIST_FROM} ${whereSql} ORDER BY ${SORTS[query.sort] || SORTS.recent} LIMIT ? OFFSET ?`,
        [...params, page.limit, page.offset]
    );
    return pageResult(rows.map(toListItem), Number(total), page);
}

async function getAccessible(user, id) {
    const row = await db.queryOne(`SELECT ${LIST_COLUMNS}, a.submitted_by ${LIST_FROM} WHERE a.id = ?`, [id]);
    // Se responde 404 (no 403) para no revelar que el análisis existe
    if (!row || (!isAnalyst(user) && row.submitted_by !== user.id)) throw notFound("Análisis no encontrado");
    return row;
}

async function getStatus(user, id) {
    const row = await getAccessible(user, id);
    return { id: row.id, status: row.status, verdict: row.verdict, riskScore: row.risk_score };
}

async function getDetail(user, id) {
    await getAccessible(user, id);

    const row = await db.queryOne(
        `SELECT ${LIST_COLUMNS}, a.score_breakdown, a.static_report, a.error_message, a.started_at,
                s.md5, s.sha1, s.mime_type, s.entropy, s.first_seen_at,
                (SELECT COUNT(*) FROM analyses x WHERE x.sample_id = a.sample_id) AS times_seen
         ${LIST_FROM} WHERE a.id = ?`,
        [id]
    );

    const [engines, indicators, rules, techniques, reviews, cases, related] = await Promise.all([
        db.query("SELECT * FROM engine_results WHERE analysis_id = ? ORDER BY id", [id]),
        db.query("SELECT type, value, is_malicious, source FROM indicators WHERE analysis_id = ? ORDER BY is_malicious DESC, type, id", [id]),
        db.query("SELECT rule_id, rule_name, severity, category, evidence FROM rule_matches WHERE analysis_id = ? ORDER BY FIELD(severity, 'critical','high','medium','low')", [id]),
        db.query(
            `SELECT t.id, t.name, t.tactic FROM analysis_techniques at INNER JOIN mitre_techniques t ON t.id = at.technique_id
             WHERE at.analysis_id = ? ORDER BY t.tactic, t.id`,
            [id]
        ),
        db.query(
            `SELECT r.id, r.verdict, r.notes, r.created_at, u.id AS analyst_id, u.full_name, p.avatar_file, p.updated_at AS avatar_v
             FROM analysis_reviews r LEFT JOIN users u ON u.id = r.analyst_id LEFT JOIN user_profiles p ON p.user_id = u.id
             WHERE r.analysis_id = ? ORDER BY r.created_at DESC`,
            [id]
        ),
        isAnalyst(user)
            ? db.query("SELECT c.id, c.code, c.title, c.status FROM case_analyses ca INNER JOIN cases c ON c.id = ca.case_id WHERE ca.analysis_id = ?", [id])
            : [],
        db.query(
            `SELECT a.id, a.original_name, a.verdict, a.risk_score, a.submitted_at FROM analyses a
             WHERE a.sample_id = (SELECT sample_id FROM analyses WHERE id = ?) AND a.id <> ? ${isAnalyst(user) ? "" : "AND a.submitted_by = ?"}
             ORDER BY a.submitted_at DESC LIMIT 5`,
            isAnalyst(user) ? [id, id] : [id, id, user.id]
        )
    ]);

    return {
        ...toListItem(row),
        errorMessage: row.error_message,
        startedAt: row.started_at,
        hashes: { md5: row.md5, sha1: row.sha1, sha256: row.sha256 },
        mimeType: row.mime_type,
        entropy: row.entropy !== null ? Number(row.entropy) : null,
        firstSeenAt: row.first_seen_at,
        timesSeen: Number(row.times_seen),
        scoreBreakdown: row.score_breakdown || [],
        staticReport: row.static_report || null,
        engines: engines.map((e) => ({
            engine: e.engine,
            name: ENGINE_NAMES[e.engine] || e.engine,
            status: e.status,
            verdict: e.verdict,
            score: e.score,
            detections: e.detections,
            total: e.total,
            summary: e.summary,
            permalink: e.permalink,
            details: e.details,
            durationMs: e.duration_ms
        })),
        indicators: indicators.map((i) => ({ type: i.type, value: i.value, isMalicious: Boolean(i.is_malicious), source: i.source })),
        rules: rules.map((r) => ({
            id: r.rule_id,
            name: r.rule_name,
            severity: r.severity,
            category: r.category,
            description: RULE_INFO[r.rule_id]?.description || null,
            techniques: RULE_INFO[r.rule_id]?.techniques || [],
            evidence: r.evidence || []
        })),
        techniques,
        reviews: reviews.map((r) => ({
            id: r.id,
            verdict: r.verdict,
            notes: r.notes,
            createdAt: r.created_at,
            analyst: r.analyst_id ? { id: r.analyst_id, fullName: r.full_name, avatarUrl: avatarUrl(r.analyst_id, r.avatar_file, r.avatar_v) } : null
        })),
        cases,
        related: related.map((r) => ({ id: r.id, originalName: r.original_name, verdict: r.verdict, riskScore: r.risk_score, submittedAt: r.submitted_at }))
    };
}

async function reanalyze(user, id) {
    const row = await getAccessible(user, id);
    if (["queued", "running"].includes(row.status)) throw badRequest("El análisis ya está en proceso");
    await db.query("UPDATE analyses SET status = 'queued', verdict = 'pending', error_message = NULL WHERE id = ?", [id]);
    queue.enqueue(id);
}

async function addReview(user, id, { verdict, notes }) {
    const row = await getAccessible(user, id);
    if (row.status !== "completed") throw badRequest("Solo se pueden revisar análisis completados");
    if (!isAnalyst(user)) throw forbidden();

    await db.transaction(async (tx) => {
        await tx.query("INSERT INTO analysis_reviews (analysis_id, analyst_id, verdict, notes) VALUES (?, ?, ?, ?)", [id, user.id, verdict, notes]);
        await tx.query("UPDATE analyses SET reviewed_verdict = ?, reviewed_at = UTC_TIMESTAMP() WHERE id = ?", [verdict, id]);
    });
}

async function dashboard(user) {
    const scope = isAnalyst(user) ? "" : "WHERE a.submitted_by = ?";
    const params = isAnalyst(user) ? [] : [user.id];

    const [[totals], timeline, recent, families, mine] = await Promise.all([
        db.query(
            `SELECT COUNT(*) AS total,
                    SUM(COALESCE(a.reviewed_verdict, a.verdict) = 'malicious') AS malicious,
                    SUM(COALESCE(a.reviewed_verdict, a.verdict) = 'suspicious') AS suspicious,
                    SUM(COALESCE(a.reviewed_verdict, a.verdict) = 'clean') AS clean,
                    SUM(a.status IN ('queued', 'running')) AS inProgress,
                    ROUND(AVG(CASE WHEN a.status = 'completed' THEN a.risk_score END)) AS avgRisk,
                    SUM(a.submitted_at >= UTC_TIMESTAMP() - INTERVAL 1 DAY) AS last24h
             FROM analyses a ${scope}`,
            params
        ),
        db.query(
            `SELECT DATE(a.submitted_at) AS day,
                    SUM(COALESCE(a.reviewed_verdict, a.verdict) = 'malicious') AS malicious,
                    SUM(COALESCE(a.reviewed_verdict, a.verdict) = 'suspicious') AS suspicious,
                    SUM(COALESCE(a.reviewed_verdict, a.verdict) = 'clean') AS clean
             FROM analyses a ${scope ? `${scope} AND` : "WHERE"} a.submitted_at >= UTC_DATE() - INTERVAL 13 DAY
             GROUP BY DATE(a.submitted_at) ORDER BY day`,
            params
        ),
        db.query(`SELECT ${LIST_COLUMNS} ${LIST_FROM} ${scope} ORDER BY a.submitted_at DESC LIMIT 6`, params),
        db.query(
            `SELECT a.threat_family AS family, COUNT(*) AS total FROM analyses a
             ${scope ? `${scope} AND` : "WHERE"} a.threat_family IS NOT NULL GROUP BY a.threat_family ORDER BY total DESC LIMIT 5`,
            params
        ),
        db.query("SELECT COUNT(*) AS total FROM analyses WHERE submitted_by = ?", [user.id])
    ]);

    const extra = {};
    if (isAnalyst(user)) {
        const [[review], [cases]] = await Promise.all([
            db.query("SELECT COUNT(*) AS total FROM analyses a WHERE a.status = 'completed' AND a.reviewed_verdict IS NULL AND (a.verdict = 'suspicious' OR (a.verdict = 'malicious' AND a.confidence < 90))"),
            db.query("SELECT SUM(status <> 'closed') AS open, SUM(status <> 'closed' AND assigned_to = ?) AS mine FROM cases", [user.id])
        ]);
        extra.pendingReview = Number(review.total) || 0;
        extra.openCases = Number(cases.open) || 0;
        extra.myCases = Number(cases.mine) || 0;
    }

    return {
        scope: isAnalyst(user) ? "global" : "personal",
        totals: {
            total: Number(totals.total) || 0,
            malicious: Number(totals.malicious) || 0,
            suspicious: Number(totals.suspicious) || 0,
            clean: Number(totals.clean) || 0,
            inProgress: Number(totals.inProgress) || 0,
            avgRisk: Number(totals.avgRisk) || 0,
            last24h: Number(totals.last24h) || 0,
            mine: Number(mine[0].total) || 0,
            ...extra
        },
        timeline: timeline.map((t) => ({ day: t.day, malicious: Number(t.malicious), suspicious: Number(t.suspicious), clean: Number(t.clean) })),
        recent: recent.map(toListItem),
        families: families.map((f) => ({ family: f.family, total: Number(f.total) }))
    };
}

module.exports = { submit, list, getStatus, getDetail, reanalyze, addReview, dashboard, isAnalyst };
