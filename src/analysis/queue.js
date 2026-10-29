/**
 * Cola de análisis en memoria con concurrencia limitada.
 * Al iniciar el servidor retoma los análisis que quedaron pendientes.
 */
const env = require("../config/env");
const db = require("../config/database");
const { runAnalysis } = require("./pipeline");

const pending = [];
let running = 0;

function enqueue(analysisId, buffer = null) {
    pending.push({ analysisId, buffer });
    drain();
}

function drain() {
    while (running < env.ANALYSIS_CONCURRENCY && pending.length) {
        const job = pending.shift();
        running++;
        runAnalysis(job.analysisId, job.buffer)
            .catch((error) => console.error("Error en la cola de análisis:", error))
            .finally(() => {
                running--;
                drain();
            });
    }
}

async function resumePending() {
    const rows = await db.query("SELECT id FROM analyses WHERE status IN ('queued', 'running') ORDER BY submitted_at");
    if (rows.length) {
        await db.query("UPDATE analyses SET status = 'queued' WHERE status = 'running'");
        rows.forEach((row) => enqueue(row.id));
        console.log(`↻ ${rows.length} análisis pendientes reanudados`);
    }
}

const stats = () => ({ pending: pending.length, running });

module.exports = { enqueue, resumePending, stats };
