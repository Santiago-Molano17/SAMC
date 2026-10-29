/**
 * Analiza las muestras de la carpeta samples/ sin base de datos.
 * Uso: npm run samples:analyze            (solo motores locales)
 *      npm run samples:analyze -- --online (incluye las APIs configuradas)
 */
const fs = require("fs");
const path = require("path");
const { analyzeBuffer } = require("../src/analysis/analyzer");

const SAMPLES_DIR = path.join(__dirname, "..", "samples");

async function main() {
    const external = process.argv.includes("--online");
    const rows = [];
    for (const file of fs.readdirSync(SAMPLES_DIR)) {
        const report = await analyzeBuffer(fs.readFileSync(path.join(SAMPLES_DIR, file)), file, { external });
        rows.push({
            archivo: file,
            tipo: report.fileInfo.label,
            veredicto: report.score.verdict,
            riesgo: report.score.score,
            familia: report.score.family || "-",
            reglas: report.ruleMatches.map((r) => r.ruleId).join(", ") || "-",
            ms: report.durationMs
        });
    }
    console.table(rows);
}

main().catch((error) => {
    console.error("❌", error.message);
    process.exit(1);
});
