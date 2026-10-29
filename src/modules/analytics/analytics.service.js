const db = require("../../config/database");
const { pageResult } = require("../../utils/pagination");

const FINAL = "COALESCE(a.reviewed_verdict, a.verdict)";
const DAY = 24 * 60 * 60 * 1000;

function resolveRange({ from, to }) {
    const end = to ? new Date(to) : new Date();
    const start = from ? new Date(from) : new Date(end.getTime() - 29 * DAY);
    start.setUTCHours(0, 0, 0, 0);
    end.setUTCHours(23, 59, 59, 999);
    const length = end.getTime() - start.getTime();
    return {
        start,
        end,
        prevStart: new Date(start.getTime() - length - 1),
        prevEnd: new Date(start.getTime() - 1),
        days: Math.round(length / DAY)
    };
}

const num = (value) => Number(value) || 0;

async function kpis(start, end) {
    const [row] = await db.query(
        `SELECT COUNT(*) AS total,
                SUM(${FINAL} = 'malicious') AS malicious,
                SUM(${FINAL} = 'suspicious') AS suspicious,
                SUM(${FINAL} = 'clean') AS clean,
                COUNT(DISTINCT a.sample_id) AS uniqueSamples,
                ROUND(AVG(CASE WHEN a.status = 'completed' THEN a.risk_score END), 1) AS avgRisk,
                ROUND(AVG(CASE WHEN a.status = 'completed' THEN TIMESTAMPDIFF(MICROSECOND, a.started_at, a.completed_at) END) / 1000) AS avgDurationMs,
                SUM(a.reviewed_verdict IS NOT NULL) AS reviewed,
                COUNT(DISTINCT a.submitted_by) AS submitters
         FROM analyses a WHERE a.submitted_at BETWEEN ? AND ?`,
        [start, end]
    );
    const total = num(row.total);
    return {
        total,
        malicious: num(row.malicious),
        suspicious: num(row.suspicious),
        clean: num(row.clean),
        uniqueSamples: num(row.uniqueSamples),
        avgRisk: num(row.avgRisk),
        avgDurationMs: num(row.avgDurationMs),
        reviewed: num(row.reviewed),
        submitters: num(row.submitters),
        detectionRate: total ? Math.round(((num(row.malicious) + num(row.suspicious)) / total) * 1000) / 10 : 0
    };
}

function delta(current, previous) {
    if (!previous) return current ? 100 : 0;
    return Math.round(((current - previous) / previous) * 1000) / 10;
}

async function overview(range) {
    const { start, end, prevStart, prevEnd } = resolveRange(range);
    const between = [start, end];

    const [
        current, previous, timeline, families, categories, fileTypes, techniques,
        riskBuckets, engines, heatmap, topIocs, topSubmitters, topRules, corrections
    ] = await Promise.all([
        kpis(start, end),
        kpis(prevStart, prevEnd),
        db.query(
            `SELECT DATE(a.submitted_at) AS day, COUNT(*) AS total,
                    SUM(${FINAL} = 'malicious') AS malicious, SUM(${FINAL} = 'suspicious') AS suspicious,
                    SUM(${FINAL} = 'clean') AS clean, ROUND(AVG(a.risk_score), 1) AS avgRisk
             FROM analyses a WHERE a.submitted_at BETWEEN ? AND ? GROUP BY DATE(a.submitted_at) ORDER BY day`,
            between
        ),
        db.query(
            `SELECT a.threat_family AS label, COUNT(*) AS total, ROUND(AVG(a.risk_score)) AS avgRisk
             FROM analyses a WHERE a.submitted_at BETWEEN ? AND ? AND a.threat_family IS NOT NULL
             GROUP BY a.threat_family ORDER BY total DESC LIMIT 10`,
            between
        ),
        db.query(
            `SELECT a.threat_category AS label, COUNT(*) AS total FROM analyses a
             WHERE a.submitted_at BETWEEN ? AND ? AND a.threat_category IS NOT NULL
             GROUP BY a.threat_category ORDER BY total DESC LIMIT 8`,
            between
        ),
        db.query(
            `SELECT s.detected_type AS label, COUNT(*) AS total, SUM(${FINAL} = 'malicious') AS malicious
             FROM analyses a INNER JOIN samples s ON s.id = a.sample_id
             WHERE a.submitted_at BETWEEN ? AND ? GROUP BY s.detected_type ORDER BY total DESC LIMIT 10`,
            between
        ),
        db.query(
            `SELECT t.id, t.name, t.tactic, COUNT(*) AS total
             FROM analysis_techniques at
             INNER JOIN analyses a ON a.id = at.analysis_id
             INNER JOIN mitre_techniques t ON t.id = at.technique_id
             WHERE a.submitted_at BETWEEN ? AND ? GROUP BY t.id, t.name, t.tactic ORDER BY total DESC`,
            between
        ),
        db.query(
            `SELECT LEAST(FLOOR(a.risk_score / 10), 9) AS bucket, COUNT(*) AS total FROM analyses a
             WHERE a.submitted_at BETWEEN ? AND ? AND a.status = 'completed' GROUP BY bucket ORDER BY bucket`,
            between
        ),
        db.query(
            `SELECT e.engine, COUNT(*) AS total, SUM(e.status = 'ok') AS ok, SUM(e.status = 'not_found') AS notFound,
                    SUM(e.status = 'error') AS errors, SUM(e.verdict = 'malicious') AS malicious, ROUND(AVG(e.duration_ms)) AS avgMs
             FROM engine_results e INNER JOIN analyses a ON a.id = e.analysis_id
             WHERE a.submitted_at BETWEEN ? AND ? GROUP BY e.engine`,
            between
        ),
        db.query(
            `SELECT WEEKDAY(a.submitted_at) AS weekday, HOUR(a.submitted_at) AS hour, COUNT(*) AS total
             FROM analyses a WHERE a.submitted_at BETWEEN ? AND ? GROUP BY weekday, hour`,
            between
        ),
        db.query(
            `SELECT i.type, i.value, COUNT(DISTINCT i.analysis_id) AS total, MAX(i.is_malicious) AS malicious
             FROM indicators i INNER JOIN analyses a ON a.id = i.analysis_id
             WHERE a.submitted_at BETWEEN ? AND ? AND i.type IN ('domain', 'ipv4', 'url')
             GROUP BY i.type, i.value ORDER BY malicious DESC, total DESC LIMIT 10`,
            between
        ),
        db.query(
            `SELECT u.id, u.full_name AS label, COUNT(*) AS total, SUM(${FINAL} = 'malicious') AS malicious
             FROM analyses a INNER JOIN users u ON u.id = a.submitted_by
             WHERE a.submitted_at BETWEEN ? AND ? GROUP BY u.id, u.full_name ORDER BY total DESC LIMIT 6`,
            between
        ),
        db.query(
            `SELECT r.rule_id, r.rule_name AS label, r.severity, COUNT(*) AS total
             FROM rule_matches r INNER JOIN analyses a ON a.id = r.analysis_id
             WHERE a.submitted_at BETWEEN ? AND ? GROUP BY r.rule_id, r.rule_name, r.severity ORDER BY total DESC LIMIT 10`,
            between
        ),
        db.query(
            `SELECT SUM(a.verdict IN ('malicious', 'suspicious') AND a.reviewed_verdict = 'clean') AS falsePositives,
                    SUM(a.verdict = 'clean' AND a.reviewed_verdict IN ('malicious', 'suspicious')) AS falseNegatives,
                    SUM(a.reviewed_verdict IS NOT NULL AND a.reviewed_verdict = a.verdict) AS confirmed
             FROM analyses a WHERE a.submitted_at BETWEEN ? AND ?`,
            between
        )
    ]);

    // Se completan los días sin actividad para que la gráfica sea continua
    const byDay = new Map(timeline.map((t) => [new Date(t.day).toISOString().slice(0, 10), t]));
    const series = [];
    for (let d = new Date(start); d <= end; d = new Date(d.getTime() + DAY)) {
        const key = d.toISOString().slice(0, 10);
        const t = byDay.get(key);
        series.push({
            day: key,
            total: num(t?.total),
            malicious: num(t?.malicious),
            suspicious: num(t?.suspicious),
            clean: num(t?.clean),
            avgRisk: t ? num(t.avgRisk) : null
        });
    }

    const tactics = {};
    for (const t of techniques) tactics[t.tactic] = (tactics[t.tactic] || 0) + num(t.total);

    const buckets = Array.from({ length: 10 }, (_, i) => ({ range: `${i * 10}-${i === 9 ? 100 : i * 10 + 9}`, total: 0 }));
    for (const b of riskBuckets) buckets[num(b.bucket)].total = num(b.total);

    return {
        range: { from: start.toISOString(), to: end.toISOString() },
        kpis: current,
        previous,
        deltas: {
            total: delta(current.total, previous.total),
            malicious: delta(current.malicious, previous.malicious),
            avgRisk: delta(current.avgRisk, previous.avgRisk),
            detectionRate: Math.round((current.detectionRate - previous.detectionRate) * 10) / 10
        },
        timeline: series,
        families: families.map((f) => ({ label: f.label, total: num(f.total), avgRisk: num(f.avgRisk) })),
        categories: categories.map((c) => ({ label: c.label, total: num(c.total) })),
        fileTypes: fileTypes.map((f) => ({ label: f.label, total: num(f.total), malicious: num(f.malicious) })),
        techniques: techniques.map((t) => ({ id: t.id, name: t.name, tactic: t.tactic, total: num(t.total) })),
        tactics: Object.entries(tactics).map(([label, total]) => ({ label, total })).sort((a, b) => b.total - a.total),
        riskBuckets: buckets,
        engines: engines.map((e) => ({
            engine: e.engine, total: num(e.total), ok: num(e.ok), notFound: num(e.notFound),
            errors: num(e.errors), malicious: num(e.malicious), avgMs: num(e.avgMs)
        })),
        heatmap: heatmap.map((h) => ({ weekday: num(h.weekday), hour: num(h.hour), total: num(h.total) })),
        topIocs: topIocs.map((i) => ({ type: i.type, value: i.value, total: num(i.total), malicious: Boolean(num(i.malicious)) })),
        topSubmitters: topSubmitters.map((s) => ({ label: s.label, total: num(s.total), malicious: num(s.malicious) })),
        topRules: topRules.map((r) => ({ id: r.rule_id, label: r.label, severity: r.severity, total: num(r.total) })),
        corrections: {
            falsePositives: num(corrections[0].falsePositives),
            falseNegatives: num(corrections[0].falseNegatives),
            confirmed: num(corrections[0].confirmed)
        }
    };
}

async function iocs({ q, type, malicious }, page) {
    const where = [];
    const params = [];
    if (q) {
        where.push("i.value LIKE ?");
        params.push(`%${q}%`);
    }
    if (type) {
        where.push("i.type = ?");
        params.push(type);
    }
    const having = malicious ? "HAVING malicious = 1" : "";
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const grouped = `
        SELECT i.type, i.value, COUNT(DISTINCT i.analysis_id) AS analyses, MAX(i.is_malicious) AS malicious,
               MAX(a.submitted_at) AS lastSeen, MIN(a.submitted_at) AS firstSeen,
               MAX(COALESCE(a.reviewed_verdict, a.verdict) = 'malicious') AS inMalicious
        FROM indicators i INNER JOIN analyses a ON a.id = i.analysis_id
        ${whereSql} GROUP BY i.type, i.value ${having}`;

    const [{ total }] = await db.query(`SELECT COUNT(*) AS total FROM (${grouped}) g`, params);
    const rows = await db.query(`${grouped} ORDER BY malicious DESC, analyses DESC, lastSeen DESC LIMIT ? OFFSET ?`, [...params, page.limit, page.offset]);
    const types = await db.query("SELECT type, COUNT(DISTINCT value) AS total FROM indicators GROUP BY type ORDER BY total DESC");

    return {
        ...pageResult(rows.map((r) => ({
            type: r.type,
            value: r.value,
            analyses: num(r.analyses),
            malicious: Boolean(num(r.malicious)),
            seenInMalicious: Boolean(num(r.inMalicious)),
            firstSeen: r.firstSeen,
            lastSeen: r.lastSeen
        })), num(total), page),
        types: types.map((t) => ({ type: t.type, total: num(t.total) }))
    };
}

async function iocAnalyses(type, value) {
    return db.query(
        `SELECT DISTINCT a.id, a.original_name, a.verdict, a.reviewed_verdict, a.risk_score, a.submitted_at
         FROM indicators i INNER JOIN analyses a ON a.id = i.analysis_id
         WHERE i.type = ? AND i.value = ? ORDER BY a.submitted_at DESC LIMIT 20`,
        [type, value]
    );
}

function csvCell(value) {
    if (value === null || value === undefined) return "";
    let text = value instanceof Date ? value.toISOString() : String(value);
    // Evita inyección de fórmulas al abrir el CSV en Excel
    if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
    return /[",\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

async function exportCsv(range) {
    const { start, end } = resolveRange(range);
    const rows = await db.query(
        `SELECT a.id, a.submitted_at, a.original_name, s.sha256, s.md5, s.detected_type, s.size_bytes,
                a.status, a.verdict, a.reviewed_verdict, a.risk_score, a.confidence, a.threat_family, a.threat_category,
                u.email AS submitted_by,
                (SELECT GROUP_CONCAT(at.technique_id ORDER BY at.technique_id SEPARATOR ' ') FROM analysis_techniques at WHERE at.analysis_id = a.id) AS techniques
         FROM analyses a INNER JOIN samples s ON s.id = a.sample_id LEFT JOIN users u ON u.id = a.submitted_by
         WHERE a.submitted_at BETWEEN ? AND ? ORDER BY a.submitted_at DESC`,
        [start, end]
    );

    const headers = ["id", "fecha", "archivo", "sha256", "md5", "tipo", "tamano_bytes", "estado", "veredicto_auto", "veredicto_analista", "riesgo", "confianza", "familia", "categoria", "enviado_por", "tecnicas_mitre"];
    const lines = rows.map((r) => [
        r.id, r.submitted_at, r.original_name, r.sha256, r.md5, r.detected_type, r.size_bytes, r.status, r.verdict,
        r.reviewed_verdict, r.risk_score, r.confidence, r.threat_family, r.threat_category, r.submitted_by, r.techniques
    ].map(csvCell).join(","));

    return "﻿" + [headers.join(","), ...lines].join("\r\n");
}

module.exports = { overview, iocs, iocAnalyses, exportCsv, resolveRange };
