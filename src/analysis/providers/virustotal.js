/**
 * VirusTotal API v3: reputación del archivo según más de 70 motores antivirus.
 * https://docs.virustotal.com/reference/overview
 */
const env = require("../../config/env");
const { request, httpError } = require("./http");

const BASE = "https://www.virustotal.com/api/v3";
const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

const headers = () => ({ "x-apikey": env.VIRUSTOTAL_API_KEY });
const permalink = (sha256) => `https://www.virustotal.com/gui/file/${sha256}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function verdictFor(malicious, suspicious, total) {
    if (malicious >= 3) return "malicious";
    if (malicious >= 1 || suspicious >= 2) return "suspicious";
    return total > 0 ? "clean" : "unknown";
}

function fromFileReport(sha256, attributes) {
    const stats = attributes.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = malicious + suspicious + (stats.undetected || 0) + (stats.harmless || 0);
    const classification = attributes.popular_threat_classification || {};

    const detectionsByEngine = Object.values(attributes.last_analysis_results || {})
        .filter((r) => r.category === "malicious" || r.category === "suspicious")
        .slice(0, 20)
        .map((r) => ({ engine: r.engine_name, result: r.result, category: r.category }));

    return {
        status: "ok",
        verdict: verdictFor(malicious, suspicious, total),
        score: total ? Math.round((malicious / total) * 100) : 0,
        detections: malicious,
        total,
        summary: total ? `${malicious} de ${total} motores lo detectan como malicioso` : "Sin resultados de motores",
        permalink: permalink(sha256),
        family: classification.suggested_threat_label || null,
        category: classification.popular_threat_category?.[0]?.value || null,
        details: {
            stats,
            detectionsByEngine,
            names: (attributes.names || []).slice(0, 5),
            typeDescription: attributes.type_description || null,
            reputation: attributes.reputation ?? null,
            tags: (attributes.tags || []).slice(0, 10),
            timesSubmitted: attributes.times_submitted ?? null,
            firstSubmission: attributes.first_submission_date ? new Date(attributes.first_submission_date * 1000).toISOString() : null,
            lastAnalysis: attributes.last_analysis_date ? new Date(attributes.last_analysis_date * 1000).toISOString() : null
        }
    };
}

async function uploadAndWait(sample, buffer) {
    const form = new FormData();
    form.append("file", new Blob([buffer]), sample.sha256);
    const upload = await request(`${BASE}/files`, { method: "POST", headers: headers(), body: form, timeoutMs: 120000 });
    if (upload.status !== 200) throw httpError(upload.status, "VirusTotal");

    const analysisId = upload.data?.data?.id;
    // Plan gratuito: 4 consultas por minuto, así que se espera con calma
    for (let attempt = 0; attempt < 3 && analysisId; attempt++) {
        await sleep(20000);
        const poll = await request(`${BASE}/analyses/${analysisId}`, { headers: headers() });
        if (poll.status === 200 && poll.data?.data?.attributes?.status === "completed") {
            const report = await request(`${BASE}/files/${sample.sha256}`, { headers: headers() });
            if (report.status === 200) return fromFileReport(sample.sha256, report.data.data.attributes);
        }
    }

    return {
        status: "not_found",
        verdict: "unknown",
        summary: "Enviado a VirusTotal; el resultado aún no está listo. Reanaliza en unos minutos",
        permalink: permalink(sample.sha256),
        details: { uploaded: true }
    };
}

module.exports = {
    id: "virustotal",
    name: "VirusTotal",
    description: "Reputación del archivo según más de 70 motores antivirus",
    url: "https://www.virustotal.com",
    requiresKey: "VIRUSTOTAL_API_KEY",
    isEnabled: () => Boolean(env.VIRUSTOTAL_API_KEY),

    async lookup({ sample, buffer }) {
        const { status, data } = await request(`${BASE}/files/${sample.sha256}`, { headers: headers() });

        if (status === 200) return fromFileReport(sample.sha256, data.data.attributes);

        if (status === 404) {
            if (env.VIRUSTOTAL_UPLOAD_UNKNOWN && buffer && buffer.length <= MAX_UPLOAD_BYTES) {
                return uploadAndWait(sample, buffer);
            }
            return { status: "not_found", verdict: "unknown", summary: "VirusTotal no conoce este archivo", permalink: permalink(sample.sha256) };
        }

        throw httpError(status, "VirusTotal");
    },

    async test() {
        const { status } = await request(`${BASE}/files/44d88612fea8a8f36de82e1278abb02f`, { headers: headers() });
        if (status === 200 || status === 404) return "Conexión correcta";
        throw httpError(status, "VirusTotal");
    }
};
