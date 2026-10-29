const express = require("express");
const { z } = require("zod");
const { authenticate, requireRole } = require("../../middleware/auth");
const { validate } = require("../../middleware/validate");
const { audit } = require("../../utils/audit");
const { ROLES } = require("../../utils/roles");
const { paginate } = require("../../utils/pagination");
const { email, password, fullName } = require("../auth/auth.schemas");
const profileService = require("../profile/profile.service");
const service = require("./users.service");

const roleEnum = z.enum(Object.values(ROLES));
const idParam = z.object({ id: z.string().uuid("Identificador inválido") });

const listSchema = z.object({
    q: z.string().trim().max(100).optional(),
    role: roleEnum.optional(),
    status: z.enum(["active", "suspended"]).optional()
});

const createSchema = z.object({
    fullName,
    email,
    password,
    role: roleEnum,
    jobTitle: z.string().trim().max(100).optional(),
    department: z.string().trim().max(100).optional()
});

const updateSchema = z.object({
    fullName: fullName.optional(),
    role: roleEnum.optional(),
    status: z.enum(["active", "suspended"]).optional(),
    unlock: z.boolean().optional()
}).refine((d) => Object.keys(d).length > 0, { message: "No hay cambios" });

// ----- /api/users: accesible para cualquier usuario autenticado -----
const publicRouter = express.Router();
publicRouter.use(authenticate);

publicRouter.get("/:id/avatar", validate(idParam, "params"), async (req, res) => {
    const { filePath, mime } = await profileService.getAvatarFile(req.valid.params.id);
    res.set({ "Content-Type": mime, "X-Content-Type-Options": "nosniff", "Cache-Control": "private, max-age=86400" });
    res.sendFile(filePath);
});

publicRouter.get("/staff", requireRole(ROLES.ANALYST), async (req, res) => {
    res.json({ items: await service.listStaff() });
});

// ----- /api/admin/users: solo ADMIN y SUPER_ADMIN -----
const adminRouter = express.Router();
adminRouter.use(authenticate, requireRole(ROLES.ADMIN));

adminRouter.get("/", validate(listSchema, "query"), async (req, res) => {
    res.json(await service.listUsers(req.valid.query, paginate(req.query)));
});

adminRouter.post("/", validate(createSchema), async (req, res) => {
    const user = await service.create(req.user, req.valid.body);
    await audit(req, "user.create", { entityType: "user", entityId: user.id, metadata: { email: user.email, role: user.role } });
    res.status(201).json({ message: "Usuario creado", user });
});

adminRouter.patch("/:id", validate(idParam, "params"), validate(updateSchema), async (req, res) => {
    const { before, after } = await service.update(req.user, req.valid.params.id, req.valid.body);
    await audit(req, "user.update", {
        entityType: "user",
        entityId: after.id,
        metadata: { changes: req.valid.body, previousRole: before.role, previousStatus: before.status }
    });
    res.json({ message: "Usuario actualizado", user: after });
});

adminRouter.delete("/:id", validate(idParam, "params"), async (req, res) => {
    const removed = await service.remove(req.user, req.valid.params.id);
    await audit(req, "user.delete", { entityType: "user", entityId: removed.id, metadata: { email: removed.email, role: removed.role } });
    res.json({ message: "Usuario eliminado" });
});

module.exports = { publicRouter, adminRouter };
