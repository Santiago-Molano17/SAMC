const express = require("express");
const { z } = require("zod");
const { authenticate, requireRole } = require("../../middleware/auth");
const { validate } = require("../../middleware/validate");
const { audit } = require("../../utils/audit");
const { ROLES } = require("../../utils/roles");
const { paginate } = require("../../utils/pagination");
const service = require("./cases.service");

const router = express.Router();
router.use(authenticate, requireRole(ROLES.ANALYST));

const statusEnum = z.enum(["open", "investigating", "contained", "closed"]);
const priorityEnum = z.enum(["low", "medium", "high", "critical"]);
const uuid = z.string().uuid("Identificador inválido");
const idParam = z.object({ id: uuid });

const listSchema = z.object({
    q: z.string().trim().max(100).optional(),
    status: z.union([statusEnum, z.literal("active")]).optional(),
    priority: priorityEnum.optional(),
    mine: z.enum(["true", "false"]).transform((v) => v === "true").optional()
});

const createSchema = z.object({
    title: z.string().trim().min(5, "Mínimo 5 caracteres").max(150),
    description: z.string().trim().max(2000).optional(),
    priority: priorityEnum.default("medium"),
    assignedTo: uuid.optional().nullable(),
    analysisIds: z.array(uuid).max(50).optional()
});

const updateSchema = z.object({
    title: z.string().trim().min(5).max(150).optional(),
    description: z.string().trim().max(2000).optional().nullable(),
    status: statusEnum.optional(),
    priority: priorityEnum.optional(),
    assignedTo: uuid.optional().nullable()
}).refine((d) => Object.keys(d).length > 0, { message: "No hay cambios" });

router.get("/", validate(listSchema, "query"), async (req, res) => {
    res.json(await service.list(req.valid.query, paginate(req.query), req.user));
});

router.post("/", validate(createSchema), async (req, res) => {
    const item = await service.create(req.user, req.valid.body);
    await audit(req, "case.create", { entityType: "case", entityId: item.id, metadata: { code: item.code } });
    res.status(201).json({ message: `Caso ${item.code} creado`, case: item });
});

router.get("/:id", validate(idParam, "params"), async (req, res) => {
    res.json({ case: await service.get(req.valid.params.id) });
});

router.patch("/:id", validate(idParam, "params"), validate(updateSchema), async (req, res) => {
    const item = await service.update(req.user, req.valid.params.id, req.valid.body);
    await audit(req, "case.update", { entityType: "case", entityId: item.id, metadata: req.valid.body });
    res.json({ message: "Caso actualizado", case: item });
});

router.post("/:id/notes", validate(idParam, "params"), validate(z.object({ body: z.string().trim().min(2).max(4000) })), async (req, res) => {
    const item = await service.addNote(req.user, req.valid.params.id, req.valid.body.body);
    await audit(req, "case.note", { entityType: "case", entityId: item.id });
    res.status(201).json({ message: "Nota agregada", case: item });
});

router.post("/:id/analyses", validate(idParam, "params"), validate(z.object({ analysisId: uuid })), async (req, res) => {
    const item = await service.linkAnalysis(req.user, req.valid.params.id, req.valid.body.analysisId);
    await audit(req, "case.link_analysis", { entityType: "case", entityId: item.id, metadata: { analysisId: req.valid.body.analysisId } });
    res.status(201).json({ message: "Análisis vinculado al caso", case: item });
});

router.delete("/:id/analyses/:analysisId", validate(z.object({ id: uuid, analysisId: uuid }), "params"), async (req, res) => {
    const item = await service.unlinkAnalysis(req.valid.params.id, req.valid.params.analysisId);
    await audit(req, "case.unlink_analysis", { entityType: "case", entityId: item.id, metadata: { analysisId: req.valid.params.analysisId } });
    res.json({ message: "Análisis desvinculado", case: item });
});

module.exports = router;
