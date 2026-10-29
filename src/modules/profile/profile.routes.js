const express = require("express");
const { z } = require("zod");
const { authenticate, signSession, setSessionCookie } = require("../../middleware/auth");
const { validate } = require("../../middleware/validate");
const { avatarUpload } = require("../../middleware/upload");
const { audit } = require("../../utils/audit");
const { password, fullName } = require("../auth/auth.schemas");
const service = require("./profile.service");

const router = express.Router();
router.use(authenticate);

const optionalText = (max) => z.string().trim().max(max, `Máximo ${max} caracteres`).optional().nullable();

const profileSchema = z.object({
    fullName,
    jobTitle: optionalText(100),
    department: optionalText(100),
    phone: z.string().trim().max(30).regex(/^[0-9+()\-\s]*$/, "Solo números, espacios y + ( ) -").optional().nullable(),
    location: optionalText(100),
    bio: optionalText(500)
});

const passwordSchema = z.object({
    currentPassword: z.string().min(1, "Ingresa tu contraseña actual"),
    newPassword: password,
    confirmPassword: z.string()
}).refine((d) => d.newPassword === d.confirmPassword, { message: "Las contraseñas no coinciden", path: ["confirmPassword"] });

router.get("/", async (req, res) => {
    res.json({ profile: await service.getProfile(req.user.id) });
});

router.patch("/", validate(profileSchema), async (req, res) => {
    const profile = await service.updateProfile(req.user.id, req.valid.body);
    await audit(req, "profile.update", { entityType: "user", entityId: req.user.id });
    res.json({ message: "Perfil actualizado", profile });
});

router.put("/password", validate(passwordSchema), async (req, res) => {
    const { currentPassword, newPassword } = req.valid.body;
    await service.changePassword(req.user.id, currentPassword, newPassword);
    await audit(req, "profile.password_change", { entityType: "user", entityId: req.user.id });

    // La sesión actual sigue activa con un token nuevo; las demás quedan invalidadas
    setSessionCookie(res, signSession(req.user));
    res.json({ message: "Contraseña actualizada" });
});

router.put("/avatar", avatarUpload, async (req, res) => {
    await service.setAvatar(req.user.id, req.file);
    await audit(req, "profile.avatar_update", { entityType: "user", entityId: req.user.id });
    res.json({ message: "Foto actualizada", profile: await service.getProfile(req.user.id) });
});

router.delete("/avatar", async (req, res) => {
    await service.removeAvatar(req.user.id);
    await audit(req, "profile.avatar_remove", { entityType: "user", entityId: req.user.id });
    res.json({ message: "Foto eliminada", profile: await service.getProfile(req.user.id) });
});

module.exports = router;
