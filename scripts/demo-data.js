/**
 * Genera un historial de análisis de ejemplo para que los paneles y la analítica
 * tengan datos. Todo el contenido es inofensivo: texto plano, el archivo de prueba
 * estándar EICAR y archivos con solo una cabecera (sin código ejecutable).
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const db = require("../src/config/database");
const { analyzeBuffer } = require("../src/analysis/analyzer");
const { saveSample } = require("../src/analysis/storage");
const RULES = require("../src/analysis/rules/definitions");

const DAYS = 30;
const SAMPLES_DIR = path.join(__dirname, "..", "samples");

const EICAR = RULES.find((r) => r.id === "eicar_test_file").patterns[0];
const headerOnly = (bytes, size = 512) => Buffer.concat([Buffer.from(bytes), Buffer.alloc(size)]);

function demoFiles() {
    const files = [];
    for (const name of fs.readdirSync(SAMPLES_DIR)) {
        files.push({ name, buffer: fs.readFileSync(path.join(SAMPLES_DIR, name)), weight: 3 });
    }

    files.push(
        { name: "eicar_prueba.com", buffer: Buffer.from(EICAR), weight: 2 },
        { name: "factura_octubre.pdf.exe", buffer: headerOnly([0x4d, 0x5a]), weight: 2 },
        { name: "foto_vacaciones.jpg", buffer: headerOnly([0x4d, 0x5a]), weight: 1 },
        { name: "acta_reunion.txt", buffer: Buffer.from("Acta de reunión del comité.\nTemas: presupuesto, cronograma y responsables.\n"), weight: 4 },
        { name: "inventario.csv", buffer: Buffer.from("producto,cantidad,precio\nteclado,12,45000\nmouse,30,22000\n"), weight: 3 },
        { name: "manual_usuario.pdf", buffer: Buffer.from("%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF"), weight: 3 },
        { name: "logo_empresa.png", buffer: headerOnly([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), weight: 3 },
        { name: "notas_proyecto.md", buffer: Buffer.from("# Proyecto\n- Revisar requisitos\n- Entregar el viernes\n"), weight: 3 }
    );

    // Variantes únicas para que cada muestra tenga su propio hash
    return files;
}

function pick(files) {
    const total = files.reduce((n, f) => n + f.weight, 0);
    let r = Math.random() * total;
    for (const file of files) {
        r -= file.weight;
        if (r <= 0) return file;
    }
    return files[0];
}

function randomDate() {
    const daysAgo = Math.floor(Math.random() * DAYS);
    const date = new Date(Date.now() - daysAgo * 86400000);
    // Más actividad en horario laboral
    const hour = Math.random() < 0.8 ? 8 + Math.floor(Math.random() * 10) : Math.floor(Math.random() * 24);
    date.setUTCHours(hour + 5, Math.floor(Math.random() * 60), Math.floor(Math.random() * 60), 0);
    return date > new Date() ? new Date(Date.now() - 3600000) : date;
}

async function persistDemo(analysisId, sampleId, report) {
    const { persist } = require("../src/analysis/pipeline");
    await persist({ id: analysisId, sample_id: sampleId }, report);
}

async function generate(userIds, count = 140) {
    const existing = await db.queryOne("SELECT COUNT(*) AS total FROM analyses");
    if (Number(existing.total) > 0) {
        console.log("  · Ya hay análisis en la base de datos; no se generan datos demo");
        return;
    }

    const submitters = Object.values(userIds);
    const analysts = [userIds["analista@sacm.local"], userIds["analista2@sacm.local"]];
    const files = demoFiles();
    const created = [];

    for (let i = 0; i < count; i++) {
        const base = pick(files);
        // Un sufijo de texto cambia el hash sin alterar el contenido relevante
        const isText = !base.buffer.subarray(0, 2).equals(Buffer.from([0x4d, 0x5a])) && base.buffer[0] !== 0x89;
        const buffer = isText && base.name !== "eicar_prueba.com"
            ? Buffer.concat([base.buffer, Buffer.from(`\n# ref ${crypto.randomBytes(4).toString("hex")}\n`)])
            : base.buffer;

        const report = await analyzeBuffer(buffer, base.name, { external: false });
        const sha256 = report.hashes.sha256;

        let sample = await db.queryOne("SELECT id FROM samples WHERE sha256 = ?", [sha256]);
        if (!sample) {
            sample = { id: crypto.randomUUID() };
            await db.query(
                "INSERT INTO samples (id, sha256, sha1, md5, size_bytes) VALUES (?, ?, ?, ?, ?)",
                [sample.id, sha256, report.hashes.sha1, report.hashes.md5, buffer.length]
            );
            await saveSample(sha256, buffer).catch(() => {});
        }

        const id = crypto.randomUUID();
        const submittedAt = randomDate();
        const startedAt = new Date(submittedAt.getTime() + 1000);
        const completedAt = new Date(startedAt.getTime() + 800 + Math.floor(Math.random() * 4000));

        await db.query(
            "INSERT INTO analyses (id, sample_id, submitted_by, original_name, submitted_at, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            [id, sample.id, submitters[Math.floor(Math.random() * submitters.length)], base.name, submittedAt, startedAt]
        );
        await persistDemo(id, sample.id, report);
        await db.query("UPDATE analyses SET completed_at = ? WHERE id = ?", [completedAt, id]);
        created.push({ id, verdict: report.score.verdict, submittedAt });
    }
    console.log(`  + ${created.length} análisis`);

    // Revisiones de analistas sobre algunos sospechosos
    let reviews = 0;
    for (const item of created.filter((c) => c.verdict === "suspicious").slice(0, 18)) {
        const verdict = Math.random() < 0.6 ? "malicious" : "clean";
        const notes = verdict === "malicious"
            ? "Confirmado tras revisar el contenido y los indicadores. Se recomienda bloquear el hash."
            : "Falso positivo: archivo de prueba interno sin comportamiento malicioso.";
        await db.query(
            "INSERT INTO analysis_reviews (analysis_id, analyst_id, verdict, notes, created_at) VALUES (?, ?, ?, ?, ?)",
            [item.id, analysts[reviews % 2], verdict, notes, new Date(item.submittedAt.getTime() + 3600000)]
        );
        await db.query("UPDATE analyses SET reviewed_verdict = ?, reviewed_at = ? WHERE id = ?", [verdict, new Date(item.submittedAt.getTime() + 3600000), item.id]);
        reviews++;
    }
    console.log(`  + ${reviews} revisiones de analistas`);

    // Casos de investigación
    const malicious = created.filter((c) => c.verdict === "malicious");
    const cases = [
        { title: "Campaña de facturas falsas con doble extensión", priority: "high", status: "investigating" },
        { title: "Pruebas de detección con archivos EICAR", priority: "low", status: "closed" },
        { title: "Documentos con notas de rescate reportados por Finanzas", priority: "critical", status: "open" }
    ];
    for (const [index, data] of cases.entries()) {
        const caseId = crypto.randomUUID();
        const code = `CASE-${new Date().getUTCFullYear()}-${String(index + 1).padStart(4, "0")}`;
        await db.query(
            "INSERT INTO cases (id, code, title, description, status, priority, created_by, assigned_to, closed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [caseId, code, data.title, "Caso de demostración generado automáticamente.", data.status, data.priority,
                analysts[0], analysts[index % 2], data.status === "closed" ? new Date() : null]
        );
        for (const item of malicious.slice(index * 3, index * 3 + 3)) {
            await db.query("INSERT IGNORE INTO case_analyses (case_id, analysis_id, added_by) VALUES (?, ?, ?)", [caseId, item.id, analysts[0]]);
        }
        await db.query("INSERT INTO case_notes (case_id, author_id, body) VALUES (?, ?, ?)", [caseId, analysts[0], `Caso abierto con prioridad ${data.priority}.`]);
    }
    console.log(`  + ${cases.length} casos`);
}

module.exports = { generate };
