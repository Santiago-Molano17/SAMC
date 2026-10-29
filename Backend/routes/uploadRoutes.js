const express = require("express");

const router = express.Router();

const multer = require("multer");

const fs = require("fs");
const path = require("path");

const { v4: uuidv4 } = require("uuid");

const db = require("../db");

const malwareAnalyzer = require("../services/malwareAnalyzer");

const { verifyToken, ROLES } = require("../middleware/authMiddleware");

const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB) || 10;

const uploadDirectory = path.join(__dirname, "..", "uploads");

if (!fs.existsSync(uploadDirectory)) {
    fs.mkdirSync(uploadDirectory, { recursive: true });
}

let schemaReadyPromise = null;

function parseJsonField(value, fallback = []) {
    if (value === null || value === undefined || value === "") {
        return fallback;
    }

    if (Array.isArray(value) || typeof value === "object") {
        return value;
    }

    try {
        return JSON.parse(value);
    } catch (error) {
        return fallback;
    }
}

function runQuery(sql) {
    return new Promise((resolve, reject) => {
        db.query(sql, (err) => {
            if (err) {
                reject(err);
                return;
            }

            resolve();
        });
    });
}

async function ensureAnalysisSchema() {
    if (!schemaReadyPromise) {
        const ignoredErrors = new Set([
            "ER_DUP_FIELDNAME",
            "ER_FK_DUP_NAME",
            "ER_DUP_KEYNAME",
            "ER_CANT_CREATE_TABLE"
        ]);

        const migrations = [
            "ALTER TABLE analysis ADD COLUMN risk_percentage INT DEFAULT 0",
            "ALTER TABLE analysis ADD COLUMN affected_system_areas JSON NULL",
            "ALTER TABLE analysis ADD COLUMN detected_capabilities JSON NULL",
            "ALTER TABLE analysis ADD COLUMN recommendation TEXT NULL",
            "ALTER TABLE analysis ADD COLUMN analyzed_by VARCHAR(36) NULL",
            "ALTER TABLE analysis ADD CONSTRAINT analysis_analyzed_by_fk FOREIGN KEY (analyzed_by) REFERENCES users(id)"
        ];

        schemaReadyPromise = migrations.reduce((promise, sql) => {
            return promise.then(() => runQuery(sql).catch((err) => {
                if (!ignoredErrors.has(err.code)) {
                    throw err;
                }
            }));
        }, Promise.resolve());
    }

    return schemaReadyPromise;
}

function writeActivityLog(userId, actionType, resourceType, resourceId, details) {
    const sql = `
        INSERT INTO activity_logs
        (user_id, action_type, resource_type, resource_id, details)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.query(sql, [userId, actionType, resourceType, resourceId, JSON.stringify(details || {})], (err) => {
        if (err) {
            console.error("No se pudo registrar actividad:", err.message);
        }
    });
}

// =========================
// MULTER CONFIG
// =========================

const storage = multer.diskStorage({

    destination: (req, file, cb) => {

        cb(null, uploadDirectory);
    },

    filename: (req, file, cb) => {

        // Solo el nombre base y caracteres seguros: evita path traversal (../) en el disco
        const safeName = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, "_").slice(-100);

        cb(
            null,
            Date.now() + "-" + safeName
        );
    }

});

const upload = multer({
    storage,
    limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 }
});

// Responde 413/400 si multer rechaza el archivo (por ejemplo, demasiado grande)
function handleUpload(req, res, next) {
    upload.single("file")(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
            return res.status(status).json({
                message: err.code === "LIMIT_FILE_SIZE"
                    ? `El archivo supera el límite de ${MAX_UPLOAD_MB} MB`
                    : "Archivo no válido"
            });
        }

        if (err) {
            return next(err);
        }

        next();
    });
}


// =========================
// UPLOAD FILE - ANÁLISIS AVANZADO
// =========================

router.post(
    "/upload",
    verifyToken,
    handleUpload,
    async (req, res) => {

        try {
            await ensureAnalysisSchema();

            const file = req.file;
            const userId = req.user.id;

            if (!file) {
                return res.status(400).json({
                    message: "Archivo requerido"
                });
            }

            // Guardar archivo en BD
            const uploadId = uuidv4();

            const uploadSql = `
                INSERT INTO uploads
                (id, user_id, original_name, file_type, file_size)
                VALUES (?, ?, ?, ?, ?)
            `;

            db.query(
                uploadSql,
                [uploadId, userId, file.originalname, file.mimetype, file.size],
                (err, result) => {

                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }

                    // Leer buffer del archivo para análisis profundo
                    fs.readFile(file.path, (readErr, fileBuffer) => {
                        if (readErr) {
                            return res.status(500).json({ error: readErr.message });
                        }

                        // Análisis inteligente
                        const analysis = malwareAnalyzer.analyze(
                            file.originalname,
                            file.size,
                            file.mimetype,
                            fileBuffer
                        );

                        // Guardar análisis en BD
                        const analysisId = uuidv4();

                        const analysisSql = `
                            INSERT INTO analysis
                            (
                                id,
                                upload_id,
                                malware_type,
                                risk_level,
                                risk_percentage,
                                vulnerabilities,
                                behavior,
                                affected_system_areas,
                                detected_capabilities,
                                recommendation,
                                analyzed_by
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `;

                        db.query(
                            analysisSql,
                            [
                                analysisId,
                                uploadId,
                                analysis.malware_type,
                                analysis.risk_level,
                                analysis.risk_percentage,
                                JSON.stringify(analysis.vulnerabilities),
                                JSON.stringify(analysis.behaviors),
                                JSON.stringify(analysis.affected_system_areas),
                                JSON.stringify(analysis.detected_capabilities),
                                analysis.recommendation,
                                userId
                            ],
                            (errAnalysis, resultAnalysis) => {

                                if (errAnalysis) {
                                    return res.status(500).json({ error: errAnalysis.message });
                                }

                                writeActivityLog(userId, "UPLOAD_ANALYSIS", "analysis", analysisId, {
                                    file: file.originalname,
                                    risk_level: analysis.risk_level,
                                    risk_percentage: analysis.risk_percentage
                                });

                                // Retornar análisis completo
                                res.json({
                                    message: "Análisis completado exitosamente",
                                    analysis_id: analysisId,
                                    upload_id: uploadId,
                                    analysis: {
                                        malware_type: analysis.malware_type,
                                        risk_level: analysis.risk_level,
                                        risk_percentage: analysis.risk_percentage,
                                        vulnerabilities: analysis.vulnerabilities,
                                        behaviors: analysis.behaviors,
                                        affected_system_areas: analysis.affected_system_areas,
                                        detected_capabilities: analysis.detected_capabilities,
                                        recommendation: analysis.recommendation,
                                        is_malware: analysis.is_malware,
                                        detection_confidence: analysis.detection_confidence,
                                        file_info: {
                                            name: file.originalname,
                                            size: file.size,
                                            type: file.mimetype
                                        }
                                    }
                                });

                            }
                        );

                    });

                }
            );

        } catch (error) {
            res.status(500).json({
                message: "Error en el servidor",
                error: error.message
            });
        }

    }
);

// =========================
// OBTENER ANÁLISIS POR ID
// =========================

router.get("/analysis/:analysisId", verifyToken, async (req, res) => {
    try {
        await ensureAnalysisSchema();
        const { analysisId } = req.params;

        const sql = `
            SELECT 
                a.*,
                u.original_name,
                u.file_size,
                u.file_type,
                u.user_id,
                user.fullname
            FROM analysis a
            INNER JOIN uploads u ON a.upload_id = u.id
            INNER JOIN users user ON u.user_id = user.id
            WHERE a.id = ?
        `;

        db.query(sql, [analysisId], (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (results.length === 0) {
                return res.status(404).json({ message: "Análisis no encontrado" });
            }

            const analysis = results[0];

            // Un USER solo puede ver sus propios análisis (evita IDOR)
            const canSeeAll = [ROLES.SUPER_ADMIN, ROLES.ADMIN, ROLES.ANALYST].includes(req.user.role);
            if (!canSeeAll && analysis.user_id !== req.user.id) {
                return res.status(404).json({ message: "Análisis no encontrado" });
            }

            res.json({
                id: analysis.id,
                upload_id: analysis.upload_id,
                malware_type: analysis.malware_type,
                risk_level: analysis.risk_level,
                risk_percentage: analysis.risk_percentage,
                vulnerabilities: parseJsonField(analysis.vulnerabilities),
                behaviors: parseJsonField(analysis.behavior),
                affected_system_areas: parseJsonField(analysis.affected_system_areas),
                detected_capabilities: parseJsonField(analysis.detected_capabilities),
                recommendation: analysis.recommendation,
                file_info: {
                    name: analysis.original_name,
                    size: analysis.file_size,
                    type: analysis.file_type
                },
                analyzed_by: analysis.fullname,
                analysis_date: analysis.analysis_date
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =========================
// OBTENER MIS ANÁLISIS
// =========================

router.get("/my-analysis", verifyToken, async (req, res) => {
    try {
        await ensureAnalysisSchema();
        const userId = req.user.id;

        const sql = `
            SELECT 
                a.id,
                a.upload_id,
                a.malware_type,
                a.risk_level,
                a.risk_percentage,
                a.analysis_date,
                u.original_name,
                u.file_size
            FROM analysis a
            INNER JOIN uploads u ON a.upload_id = u.id
            WHERE u.user_id = ?
            ORDER BY a.analysis_date DESC
            LIMIT 50
        `;

        db.query(sql, [userId], (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                message: "Análisis obtenidos",
                total: results.length,
                analysis: results
            });
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
