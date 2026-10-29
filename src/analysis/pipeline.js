/**
 * Ejecuta un análisis en segundo plano y guarda todos los resultados.
 */
const db = require("../config/database");
const { analyzeBuffer } = require("./analyzer");
const { readSample } = require("./storage");
const { PROVIDERS, LOCAL_ENGINES } = require("./providers");

const ENGINE_ORDER = [...LOCAL_ENGINES.map((e) => e.id), ...PROVIDERS.map((p) => p.id)];

async function runAnalysis(analysisId, bufferHint = null) {
    const analysis = await db.queryOne(
        `SELECT a.id, a.original_name, s.id AS sample_id, s.sha256
         FROM analyses a INNER JOIN samples s ON s.id = a.sample_id WHERE a.id = ?`,
        [analysisId]
    );
    if (!analysis) return;

    await db.query("UPDATE analyses SET status = 'running', started_at = UTC_TIMESTAMP(), error_message = NULL WHERE id = ?", [analysisId]);

    try {
        const buffer = bufferHint || (await readSample(analysis.sha256));
        if (!buffer) throw new Error("El archivo ya no está disponible en el almacén de muestras");

        const report = await analyzeBuffer(buffer, analysis.original_name);
        await persist(analysis, report);
    } catch (error) {
        console.error(`Análisis ${analysisId} falló:`, error);
        await db.query(
            "UPDATE analyses SET status = 'failed', completed_at = UTC_TIMESTAMP(), error_message = ? WHERE id = ?",
            [error.message.slice(0, 500), analysisId]
        );
    }
}

async function persist(analysis, report) {
    const { score, fileInfo, entropy, pe, strings } = report;

    const staticReport = {
        file: {
            type: fileInfo.type,
            label: fileInfo.label,
            category: fileInfo.category,
            mime: fileInfo.mime,
            extension: fileInfo.extension,
            mismatch: fileInfo.mismatch,
            doubleExtension: fileInfo.doubleExtension,
            hasMacros: fileInfo.hasMacros
        },
        entropy,
        pe,
        strings,
        durationMs: report.durationMs
    };

    await db.transaction(async (tx) => {
        // Si es un reanálisis se reemplazan los resultados anteriores
        for (const table of ["engine_results", "indicators", "rule_matches", "analysis_techniques"]) {
            await tx.query(`DELETE FROM ${table} WHERE analysis_id = ?`, [analysis.id]);
        }

        const engineRows = Object.entries(report.engines)
            .sort(([a], [b]) => ENGINE_ORDER.indexOf(a) - ENGINE_ORDER.indexOf(b))
            .map(([engine, r]) => [
                analysis.id, engine, r.status, r.verdict || "unknown",
                r.score ?? null, r.detections ?? null, r.total ?? null,
                (r.summary || "").slice(0, 255), r.permalink || null,
                r.details ? JSON.stringify(r.details) : null, r.durationMs ?? null
            ]);
        if (engineRows.length) {
            await tx.query(
                `INSERT INTO engine_results (analysis_id, engine, status, verdict, score, detections, total, summary, permalink, details, duration_ms) VALUES ?`,
                [engineRows]
            );
        }

        if (report.indicators.length) {
            await tx.query(
                "INSERT INTO indicators (analysis_id, type, value, is_malicious, source) VALUES ?",
                [report.indicators.map((i) => [analysis.id, i.type, i.value, Boolean(i.isMalicious), i.source || null])]
            );
        }

        if (report.ruleMatches.length) {
            await tx.query(
                "INSERT INTO rule_matches (analysis_id, rule_id, rule_name, severity, category, evidence) VALUES ?",
                [report.ruleMatches.map((r) => [analysis.id, r.ruleId, r.name, r.severity, r.category, JSON.stringify(r.evidence)])]
            );
        }

        const techniques = [...new Set(report.ruleMatches.flatMap((r) => r.techniques))];
        if (fileInfo.doubleExtension) techniques.push("T1036.007");
        if (fileInfo.mismatch) techniques.push("T1036.008");
        if (pe?.packers?.length && !techniques.includes("T1027.002")) techniques.push("T1027.002");
        if (techniques.length) {
            await tx.query("INSERT IGNORE INTO analysis_techniques (analysis_id, technique_id) VALUES ?", [techniques.map((t) => [analysis.id, t])]);
        }

        await tx.query(
            `UPDATE samples SET detected_type = ?, mime_type = ?, entropy = ? WHERE id = ?`,
            [fileInfo.type, fileInfo.mime, entropy.overall, analysis.sample_id]
        );

        await tx.query(
            `UPDATE analyses SET status = 'completed', verdict = ?, risk_score = ?, confidence = ?, threat_family = ?,
                threat_category = ?, score_breakdown = ?, static_report = ?, completed_at = UTC_TIMESTAMP()
             WHERE id = ?`,
            [
                score.verdict, score.score, score.confidence, score.family, score.category,
                JSON.stringify(score.reasons), JSON.stringify(staticReport), analysis.id
            ]
        );
    });
}

module.exports = { runAnalysis, persist };
