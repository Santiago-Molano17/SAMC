const express = require("express");
const { z } = require("zod");
const { authenticate, requireRole } = require("../../middleware/auth");
const { validate } = require("../../middleware/validate");
const { sampleUpload } = require("../../middleware/upload");
const { uploadLimiter } = require("../../middleware/rateLimit");
const { audit } = require("../../utils/audit");
const { ROLES } = require("../../utils/roles");
const { paginate } = require("../../utils/pagination");
const env = require("../../config/env");
const { describeIntegrations } = require("../../analysis/providers");
const service = require("./analyses.service");

const router = express.Router();
router.use(authenticate);

const verdictEnum = z.enum(["clean", "suspicious", "malicious"]);
const idParam = z.object({ id: z.string().uuid("Identificador inválido") });

const listSchema = z.object({
    q: z.string().trim().max(128).optional(),
    verdict: verdictEnum.optional(),
    status: z.enum(["queued", "running", "completed", "failed"]).optional(),
    scope: z.enum(["all", "mine"]).optional(),
    sort: z.enum(["recent", "risk", "name"]).optional(),
    from: z.coerce.date().optional(),
    to: z.coerce.date().optional(),
    needsReview: z.enum(["true", "false"]).transform((v) => v === "true").optional(),
    technique: z.string().regex(/^T\d{4}(\.\d{3})?$/).optional(),
    family: z.string().trim().max(100).optional()
});

const reviewSchema = z.object({
    verdict: verdictEnum,
    notes: z.string().trim().min(10, "Explica tu decisión (mínimo 10 caracteres)").max(2000)
});

router.get("/engines", (req, res) => {
    res.json({ items: describeIntegrations(), maxUploadMb: env.MAX_UPLOAD_MB });
});

router.get("/dashboard", async (req, res) => {
    res.json(await service.dashboard(req.user));
});

router.post("/", uploadLimiter, sampleUpload, async (req, res) => {
    const result = await service.submit(req.user, req.file);
    await audit(req, "analysis.submit", { entityType: "analysis", entityId: result.id, metadata: { file: result.originalName, sha256: result.sha256 } });
    res.status(202).json({ message: "Archivo recibido. Análisis en curso", analysis: result });
});

router.get("/", validate(listSchema, "query"), async (req, res) => {
    res.json(await service.list(req.user, req.valid.query, paginate(req.query)));
});

router.get("/:id", validate(idParam, "params"), async (req, res) => {
    res.json({ analysis: await service.getDetail(req.user, req.valid.params.id) });
});

router.get("/:id/status", validate(idParam, "params"), async (req, res) => {
    res.json(await service.getStatus(req.user, req.valid.params.id));
});

router.get("/:id/report", validate(idParam, "params"), async (req, res) => {
    const analysis = await service.getDetail(req.user, req.valid.params.id);
    await audit(req, "analysis.export", { entityType: "analysis", entityId: analysis.id });
    const name = `sacm-reporte-${analysis.hashes.sha256.slice(0, 12)}.json`;
    res.set("Content-Disposition", `attachment; filename="${name}"`);
    res.json({ generatedAt: new Date().toISOString(), generator: "SACM v2", analysis });
});

router.post("/:id/reanalyze", requireRole(ROLES.ANALYST), validate(idParam, "params"), async (req, res) => {
    await service.reanalyze(req.user, req.valid.params.id);
    await audit(req, "analysis.reanalyze", { entityType: "analysis", entityId: req.valid.params.id });
    res.status(202).json({ message: "Reanálisis en curso" });
});

router.post("/:id/reviews", requireRole(ROLES.ANALYST), validate(idParam, "params"), validate(reviewSchema), async (req, res) => {
    await service.addReview(req.user, req.valid.params.id, req.valid.body);
    await audit(req, "analysis.review", { entityType: "analysis", entityId: req.valid.params.id, metadata: { verdict: req.valid.body.verdict } });
    res.status(201).json({ message: "Revisión registrada", analysis: await service.getDetail(req.user, req.valid.params.id) });
});

module.exports = router;
