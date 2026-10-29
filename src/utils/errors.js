class AppError extends Error {
    constructor(status, message, details) {
        super(message);
        this.status = status;
        this.details = details;
    }
}

const badRequest = (message, details) => new AppError(400, message, details);
const unauthorized = (message = "Debes iniciar sesión") => new AppError(401, message);
const forbidden = (message = "No tienes permisos para esta acción") => new AppError(403, message);
const notFound = (message = "Recurso no encontrado") => new AppError(404, message);
const conflict = (message) => new AppError(409, message);

module.exports = { AppError, badRequest, unauthorized, forbidden, notFound, conflict };
