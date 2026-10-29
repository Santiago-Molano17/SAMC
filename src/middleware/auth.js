const jwt = require("jsonwebtoken");
const env = require("../config/env");
const db = require("../config/database");
const { unauthorized, forbidden } = require("../utils/errors");
const { hasLevel } = require("../utils/roles");

const COOKIE_NAME = "sacm_session";
const JWT_OPTIONS = { issuer: "SACM", audience: "SACM-APP" };

function signSession(user) {
    return jwt.sign({ sub: user.id, role: user.role }, env.JWT_SECRET, {
        ...JWT_OPTIONS,
        expiresIn: env.JWT_EXPIRES_IN
    });
}

/** Cookie httpOnly: el token nunca queda expuesto a JavaScript (mitiga robo por XSS) */
function setSessionCookie(res, token) {
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: "strict",
        secure: env.isProduction,
        path: "/",
        maxAge: 1000 * 60 * 60 * 12
    });
}

function clearSessionCookie(res) {
    res.clearCookie(COOKIE_NAME, { path: "/" });
}

/**
 * Verifica el token y vuelve a cargar al usuario desde la base de datos,
 * así una suspensión o un cambio de rol aplica de inmediato.
 */
async function authenticate(req, res, next) {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) return next(unauthorized());

    let payload;
    try {
        payload = jwt.verify(token, env.JWT_SECRET, JWT_OPTIONS);
    } catch {
        clearSessionCookie(res);
        return next(unauthorized("Tu sesión expiró. Inicia sesión de nuevo"));
    }

    const user = await db.queryOne(
        `SELECT u.id, u.full_name, u.email, u.status, u.password_changed_at, r.code AS role
         FROM users u INNER JOIN roles r ON r.id = u.role_id
         WHERE u.id = ?`,
        [payload.sub]
    );

    if (!user || user.status !== "active") {
        clearSessionCookie(res);
        return next(unauthorized("Tu cuenta no está activa"));
    }

    // Un cambio de contraseña invalida las sesiones emitidas antes
    if (user.password_changed_at && payload.iat * 1000 < new Date(user.password_changed_at).getTime() - 1000) {
        clearSessionCookie(res);
        return next(unauthorized("Tu contraseña cambió. Inicia sesión de nuevo"));
    }

    req.user = { id: user.id, fullName: user.full_name, email: user.email, role: user.role };
    next();
}

/** Exige un rol mínimo según la jerarquía USER < ANALYST < ADMIN < SUPER_ADMIN */
const requireRole = (minimum) => (req, res, next) => {
    if (!req.user) return next(unauthorized());
    if (!hasLevel(req.user.role, minimum)) return next(forbidden());
    next();
};

module.exports = { authenticate, requireRole, signSession, setSessionCookie, clearSessionCookie };
