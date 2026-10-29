const express = require("express");
const { z } = require("zod");
const { authenticate, requireRole } = require("../../middleware/auth");
const { validate } = require("../../middleware/validate");
const { audit } = require("../../utils/audit");
const { ROLES } = require("../../utils/roles");
const { paginate } = require("../../utils/pagination");
const service = require("./analytics.service");

const router = express.Router();
router.use(authenticate, requireRole(ROLES.ANALYST));

const rangeSchema = z.object({
    from: z.coerce.date().optional(),
    to: z.coerce.date().optional()
}).refine((r) => !r.from || !r.to || r.from <= r.to, { message: "La fecha inicial debe ser anterior a la final", path: ["from"] });

const iocTypes = z.enum(["url", "domain", "ipv4", "email", "registry", "path", "bitcoin"]);

const iocListSchema = z.object({
    q: z.string().trim().max(200).optional(),
    type: iocTypes.optional(),
    malicious: z.enum(["true", "false"]).transform((v) => v === "true").optional()
});

router.get("/overview", validate(rangeSchema, "query"), async (req, res) => {
    res.json(await service.overview(req.valid.query));
});

router.get("/iocs", validate(iocListSchema, "query"), async (req, res) => {
    res.json(await service.iocs(req.valid.query, paginate(req.query)));
});

router.get("/iocs/analyses", validate(z.object({ type: iocTypes, value: z.string().min(1).max(500) }), "query"), async (req, res) => {
    const rows = await service.iocAnalyses(req.valid.query.type, req.valid.query.value);
    res.json({
        items: rows.map((r) => ({
            id: r.id, originalName: r.original_name, finalVerdict: r.reviewed_verdict || r.verdict,
            riskScore: r.risk_score, submittedAt: r.submitted_at
        }))
    });
});

router.get("/export.csv", validate(rangeSchema, "query"), async (req, res) => {
    const csv = await service.exportCsv(req.valid.query);
    await audit(req, "analytics.export", { metadata: req.valid.query });
    res.set({
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="sacm-analisis-${new Date().toISOString().slice(0, 10)}.csv"`
    });
    res.send(csv);
});

module.exports = router;
