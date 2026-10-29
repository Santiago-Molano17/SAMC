const multer = require("multer");
const env = require("../config/env");
const { AppError } = require("../utils/errors");

function notFoundHandler(req, res) {
    res.status(404).json({ message: "Ruta no encontrada" });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
    if (err instanceof AppError) {
        return res.status(err.status).json({ message: err.message, fields: err.details });
    }

    if (err instanceof multer.MulterError) {
        const tooBig = err.code === "LIMIT_FILE_SIZE";
        return res.status(tooBig ? 413 : 400).json({
            message: tooBig ? `El archivo supera el límite de ${env.MAX_UPLOAD_MB} MB` : "Archivo no válido"
        });
    }

    if (err.type === "entity.too.large") {
        return res.status(413).json({ message: "La solicitud es demasiado grande" });
    }

    if (err.type === "entity.parse.failed") {
        return res.status(400).json({ message: "JSON inválido" });
    }

    // Errores inesperados: se registran completos pero nunca se envían al cliente
    console.error(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`, err);
    res.status(500).json({ message: "Error interno del servidor" });
}

module.exports = { notFoundHandler, errorHandler };
