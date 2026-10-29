const express = require("express");
const { validate } = require("../../middleware/validate");
const { authLimiter } = require("../../middleware/rateLimit");
const { authenticate, signSession, setSessionCookie, clearSessionCookie } = require("../../middleware/auth");
const { audit } = require("../../utils/audit");
const { registerSchema, loginSchema } = require("./auth.schemas");
const service = require("./auth.service");

const router = express.Router();

router.post("/register", authLimiter, validate(registerSchema), async (req, res) => {
    const { fullName, email, password } = req.valid.body;
    const userId = await service.createUser({ fullName, email, password });

    await audit(req, "auth.register", { entityType: "user", entityId: userId, userId });
    res.status(201).json({ message: "Cuenta creada. Ya puedes iniciar sesión" });
});

router.post("/login", authLimiter, validate(loginSchema), async (req, res) => {
    const { email, password } = req.valid.body;

    try {
        const user = await service.login(email, password);
        setSessionCookie(res, signSession(user));
        await audit(req, "auth.login", { entityType: "user", entityId: user.id, userId: user.id });
        res.json({ user: await service.getSessionUser(user.id) });
    } catch (error) {
        await audit(req, "auth.login_failed", {
            userId: error.userId || null,
            metadata: { email, reason: error.message }
        });
        throw error;
    }
});

router.post("/logout", authenticate, async (req, res) => {
    await audit(req, "auth.logout");
    clearSessionCookie(res);
    res.json({ message: "Sesión cerrada" });
});

router.get("/me", authenticate, async (req, res) => {
    res.json({ user: await service.getSessionUser(req.user.id) });
});

module.exports = router;
