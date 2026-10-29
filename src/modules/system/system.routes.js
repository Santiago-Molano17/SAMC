const express = require("express");
const { z } = require("zod");
const db = require("../../config/database");
const env = require("../../config/env");
const { authenticate, requireRole } = require("../../middleware/auth");
const { validate } = require("../../middleware/validate");
const { audit } = require("../../utils/audit");
const { ROLES } = require("../../utils/roles");
const { badRequest, notFound } = require("../../utils/errors");
const { describeIntegrations, getProvider } = require("../../analysis/providers");
const { RULES } = require("../../analysis/rules/engine");
const queue = require("../../analysis/queue");

const router = express.Router();
router.use(authenticate, requireRole(ROLES.ADMIN));

router.get("/overview", async (req, res) => {
    const started = Date.now();
    await db.query("SELECT 1");
    const dbLatencyMs = Date.now() - started;

    const [[storage], usage, [techniques]] = await Promise.all([
        db.query("SELECT COUNT(*) AS samples, COALESCE(SUM(size_bytes), 0) AS bytes FROM samples"),
        db.query(
            `SELECT engine, COUNT(*) AS total, SUM(status = 'error') AS errors, MAX(created_at) AS lastUsed
             FROM engine_results WHERE created_at >= UTC_TIMESTAMP() - INTERVAL 30 DAY GROUP BY engine`
        ),
        db.query("SELECT COUNT(*) AS total FROM mitre_techniques")
    ]);

    const usageByEngine = Object.fromEntries(usage.map((u) => [u.engine, { total: Number(u.total), errors: Number(u.errors), lastUsed: u.lastUsed }]));

    res.json({
        integrations: describeIntegrations().map((i) => ({ ...i, usage: usageByEngine[i.id] || { total: 0, errors: 0, lastUsed: null } })),
        health: {
            status: "ok",
            uptimeSec: Math.round(process.uptime()),
            node: process.version,
            environment: env.NODE_ENV,
            dbLatencyMs,
            queue: queue.stats(),
            memoryMb: Math.round(process.memoryUsage().rss / 1024 / 1024)
        },
        storage: { samples: Number(storage.samples), bytes: Number(storage.bytes) },
        engine: {
            rules: RULES.length,
            techniques: Number(techniques.total),
            maxUploadMb: env.MAX_UPLOAD_MB,
            virusTotalUpload: env.VIRUSTOTAL_UPLOAD_UNKNOWN
        }
    });
});

router.get("/rules", async (req, res) => {
    const usage = await db.query("SELECT rule_id, COUNT(*) AS total FROM rule_matches GROUP BY rule_id");
    const byRule = Object.fromEntries(usage.map((u) => [u.rule_id, Number(u.total)]));
    res.json({
        items: RULES.map((r) => ({
            id: r.id,
            name: r.name,
            description: r.description,
            severity: r.severity,
            category: r.category,
            techniques: r.techniques,
            patterns: r.patterns.length,
            min: r.min || 1,
            matches: byRule[r.id] || 0
        }))
    });
});

router.post("/integrations/:id/test", requireRole(ROLES.SUPER_ADMIN), validate(z.object({ id: z.string().max(40) }), "params"), async (req, res) => {
    const provider = getProvider(req.valid.params.id);
    if (!provider) throw notFound("Integración no encontrada");
    if (!provider.isEnabled()) throw badRequest(`Configura ${provider.requiresKey} en el archivo .env para activarla`);

    const started = Date.now();
    try {
        const message = await provider.test();
        await audit(req, "system.integration_test", { metadata: { provider: provider.id, ok: true } });
        res.json({ ok: true, message, latencyMs: Date.now() - started });
    } catch (error) {
        await audit(req, "system.integration_test", { metadata: { provider: provider.id, ok: false, error: error.message } });
        res.json({ ok: false, message: error.message, latencyMs: Date.now() - started });
    }
});

module.exports = router;
