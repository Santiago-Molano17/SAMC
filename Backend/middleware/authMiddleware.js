const jwt = require("jsonwebtoken");

// =========================
// VERIFICAR TOKEN
// =========================

exports.verifyToken = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "Token requerido"
            });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({
                    message: "Token inválido o expirado"
                });
            }

            req.user = decoded;
            next();
        });

    } catch (error) {
        res.status(500).json({
            message: "Error de autenticación",
            error: error.message
        });
    }
};

// =========================
// VERIFICAR ROL
// =========================

exports.verifyRole = (allowedRoles) => {
    return (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({
                    message: "Usuario no autenticado"
                });
            }

            if (!allowedRoles.includes(req.user.role)) {
                return res.status(403).json({
                    message: "Acceso denegado. Rol insuficiente"
                });
            }

            next();

        } catch (error) {
            res.status(500).json({
                message: "Error de autorización",
                error: error.message
            });
        }
    };
};

// =========================
// ROLES DISPONIBLES
// =========================

exports.ROLES = {
    SUPER_ADMIN: "SUPER_ADMIN",
    ADMIN: "ADMIN",
    ANALYST: "ANALYST",
    USER: "USER"
};
