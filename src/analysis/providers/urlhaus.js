/**
 * URLhaus (abuse.ch): reputación de los dominios e IP encontrados dentro del archivo.
 * https://urlhaus-api.abuse.ch/
 */
const env = require("../../config/env");
const { request, httpError, ProviderError } = require("./http");

const API = "https://urlhaus-api.abuse.ch/v1/host/";
const MAX_HOSTS = 6;

function hostsFrom(indicators) {
    const hosts = new Set();
    for (const ioc of indicators) {
        if (ioc.type === "domain" || ioc.type === "ipv4") hosts.add(ioc.value);
        if (ioc.type === "url") {
            try {
                hosts.add(new URL(ioc.value).hostname.toLowerCase());
            } catch {
                // URL inválida
            }
        }
    }
    return [...hosts].slice(0, MAX_HOSTS);
}

module.exports = {
    id: "urlhaus",
    name: "URLhaus",
    description: "Reputación de dominios e IP usados para distribuir malware (abuse.ch)",
    url: "https://urlhaus.abuse.ch",
    requiresKey: "ABUSECH_AUTH_KEY",
    isEnabled: () => Boolean(env.ABUSECH_AUTH_KEY),

    async lookup({ indicators }) {
        const hosts = hostsFrom(indicators);
        if (hosts.length === 0) {
            return { status: "skipped", verdict: "unknown", summary: "El archivo no contiene dominios ni IP para consultar" };
        }

        const results = [];
        for (const host of hosts) {
            const { status, data } = await request(API, {
                method: "POST",
                headers: { "Auth-Key": env.ABUSECH_AUTH_KEY },
                body: new URLSearchParams({ host }),
                timeoutMs: 10000
            });
            if (status !== 200) throw httpError(status, "URLhaus");
            if (data?.query_status === "unknown_auth_key") throw new ProviderError("Auth-Key de abuse.ch inválida");

            const listed = data?.query_status === "ok" && Number(data.url_count) > 0;
            results.push({
                host,
                listed,
                urlCount: Number(data?.url_count) || 0,
                threats: [...new Set((data?.urls || []).map((u) => u.threat).filter(Boolean))].slice(0, 3),
                tags: [...new Set((data?.urls || []).flatMap((u) => u.tags || []))].slice(0, 5),
                reference: data?.urlhaus_reference || null
            });
        }

        const malicious = results.filter((r) => r.listed);
        return {
            status: "ok",
            verdict: malicious.length ? "malicious" : "clean",
            score: malicious.length ? 90 : 0,
            detections: malicious.length,
            total: results.length,
            summary: malicious.length
                ? `${malicious.length} de ${results.length} dominios/IP distribuyen malware`
                : `${results.length} dominios/IP consultados, ninguno reportado`,
            permalink: "https://urlhaus.abuse.ch/browse/",
            maliciousHosts: malicious.map((r) => r.host),
            details: { hosts: results }
        };
    },

    async test() {
        const { status, data } = await request(API, {
            method: "POST",
            headers: { "Auth-Key": env.ABUSECH_AUTH_KEY },
            body: new URLSearchParams({ host: "example.com" })
        });
        if (status !== 200) throw httpError(status, "URLhaus");
        if (data?.query_status === "unknown_auth_key") throw new ProviderError("Auth-Key de abuse.ch inválida");
        return "Conexión correcta";
    }
};
