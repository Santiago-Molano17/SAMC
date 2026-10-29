const rateLimit = require("express-rate-limit");

const message = (text) => ({ message: text });

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 600,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: message("Demasiadas solicitudes. Intenta de nuevo en unos minutos")
});

// Protección contra fuerza bruta en login y registro
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: message("Demasiados intentos. Espera 15 minutos")
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 60,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: message("Alcanzaste el límite de análisis por hora")
});

module.exports = { apiLimiter, authLimiter, uploadLimiter };
