class ProviderError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
    }
}

/** fetch con tiempo límite y errores legibles para el analista */
async function request(url, { method = "GET", headers = {}, body, timeoutMs = 15000 } = {}) {
    let response;
    try {
        response = await fetch(url, {
            method,
            headers: { "User-Agent": "SACM/2.0 (+malware-analysis)", Accept: "application/json", ...headers },
            body,
            signal: AbortSignal.timeout(timeoutMs)
        });
    } catch (error) {
        const reason = error.name === "TimeoutError" ? "tiempo de espera agotado" : "sin conexión";
        throw new ProviderError(`No se pudo contactar el servicio (${reason})`);
    }

    const text = await response.text();
    let data = null;
    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = { raw: text.slice(0, 500) };
    }
    return { status: response.status, data };
}

function httpError(status, service) {
    if (status === 401 || status === 403) return new ProviderError(`API key de ${service} inválida o sin permisos`, status);
    if (status === 429) return new ProviderError(`Se alcanzó el límite de consultas de ${service}`, status);
    return new ProviderError(`${service} respondió con estado ${status}`, status);
}

module.exports = { request, httpError, ProviderError };
