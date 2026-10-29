/**
 * CIRCL hashlookup: identifica archivos legítimos conocidos (NSRL, distribuciones Linux, etc.).
 * Servicio público, no requiere API key. https://www.circl.lu/services/hashlookup/
 */
const env = require("../../config/env");
const { request, httpError } = require("./http");

const BASE = "https://hashlookup.circl.lu";

module.exports = {
    id: "circl_hashlookup",
    name: "CIRCL hashlookup",
    description: "Base de archivos legítimos conocidos (NSRL y repositorios de software)",
    url: "https://hashlookup.circl.lu",
    requiresKey: null,
    isEnabled: () => env.CIRCL_HASHLOOKUP_ENABLED,

    async lookup({ sample }) {
        const url = `${BASE}/lookup/sha1/${sample.sha1}`;
        const { status, data } = await request(url, { timeoutMs: 10000 });

        if (status === 404) {
            return { status: "not_found", verdict: "unknown", summary: "No figura en bases de software legítimo", permalink: url };
        }
        if (status !== 200) throw httpError(status, "CIRCL");

        const knownMalicious = data.KnownMalicious || data["hashlookup:KnownMalicious"] || null;
        const trust = Number(data["hashlookup:trust"] ?? 50);
        const product = data.ProductCode?.ProductName || data.ProductName || null;

        return {
            status: "ok",
            verdict: knownMalicious ? "malicious" : "clean",
            score: trust,
            summary: knownMalicious
                ? `Marcado como malicioso por ${knownMalicious}`
                : `Software legítimo conocido${product ? `: ${product}` : ""} (confianza ${trust}/100)`,
            permalink: url,
            details: {
                fileName: data.FileName || null,
                product,
                vendor: data.ProductCode?.MfgCode ? `Fabricante #${data.ProductCode.MfgCode}` : null,
                source: data.source || data.db || null,
                trust,
                knownMalicious,
                parents: (data.parents || []).slice(0, 5).map((p) => p.FileName || p["SHA-1"])
            }
        };
    },

    async test() {
        const { status } = await request(`${BASE}/lookup/md5/8ED4B4ED952526D89899E723F3488DE4`, { timeoutMs: 10000 });
        if (status === 200 || status === 404) return "Conexión correcta";
        throw httpError(status, "CIRCL");
    }
};
