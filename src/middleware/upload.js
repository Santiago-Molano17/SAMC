const multer = require("multer");
const env = require("../config/env");

// Los archivos se reciben en memoria: se calcula su hash antes de guardarlos,
// y se guardan con el SHA-256 como nombre (nunca con el nombre del usuario).
const sampleUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: env.MAX_UPLOAD_MB * 1024 * 1024, files: 1, fields: 5 }
}).single("file");

const avatarUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024, files: 1, fields: 0 }
}).single("avatar");

module.exports = { sampleUpload, avatarUpload };
