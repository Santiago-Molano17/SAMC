/**
 * Cliente de la API. La sesión viaja en una cookie httpOnly, así que el
 * token nunca está disponible para JavaScript.
 */

export class ApiError extends Error {
    constructor(status, message, fields) {
        super(message);
        this.status = status;
        this.fields = fields;
    }
}

let onUnauthorized = null;
export const setUnauthorizedHandler = (handler) => { onUnauthorized = handler; };

function buildUrl(path, params) {
    const url = new URL(`/api${path}`, location.origin);
    for (const [key, value] of Object.entries(params || {})) {
        if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, value);
    }
    return url;
}

async function parse(response) {
    const type = response.headers.get("content-type") || "";
    return type.includes("application/json") ? response.json() : response.text();
}

export async function request(method, path, { body, params, signal } = {}) {
    const options = { method, credentials: "same-origin", headers: { Accept: "application/json" }, signal };

    if (body instanceof FormData) {
        options.body = body;
    } else if (body !== undefined) {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(body);
    }

    let response;
    try {
        response = await fetch(buildUrl(path, params), options);
    } catch (error) {
        if (error.name === "AbortError") throw error;
        throw new ApiError(0, "No hay conexión con el servidor");
    }

    const data = await parse(response).catch(() => null);

    if (!response.ok) {
        if (response.status === 401 && onUnauthorized && !path.startsWith("/auth/login")) onUnauthorized();
        throw new ApiError(response.status, data?.message || "Ocurrió un error inesperado", data?.fields);
    }
    return data;
}

/** Subida con progreso (fetch no informa el avance de la carga) */
export function upload(path, formData, onProgress) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", `/api${path}`);
        xhr.withCredentials = true;
        xhr.setRequestHeader("Accept", "application/json");
        xhr.upload.addEventListener("progress", (event) => {
            if (event.lengthComputable && onProgress) onProgress(Math.round((event.loaded / event.total) * 100));
        });
        xhr.addEventListener("load", () => {
            let data = null;
            try { data = JSON.parse(xhr.responseText); } catch { /* respuesta vacía */ }
            if (xhr.status >= 200 && xhr.status < 300) resolve(data);
            else {
                if (xhr.status === 401 && onUnauthorized) onUnauthorized();
                reject(new ApiError(xhr.status, data?.message || "No se pudo subir el archivo", data?.fields));
            }
        });
        xhr.addEventListener("error", () => reject(new ApiError(0, "No hay conexión con el servidor")));
        xhr.send(formData);
    });
}

/** Descarga un archivo de la API (reportes, CSV) */
export async function download(path, params) {
    const response = await fetch(buildUrl(path, params), { credentials: "same-origin" });
    if (!response.ok) {
        const data = await parse(response).catch(() => null);
        throw new ApiError(response.status, data?.message || "No se pudo descargar");
    }
    const disposition = response.headers.get("content-disposition") || "";
    const name = /filename="?([^"]+)"?/.exec(disposition)?.[1] || "descarga";
    return { blob: await response.blob(), name };
}

export const api = {
    get: (path, params, signal) => request("GET", path, { params, signal }),
    post: (path, body) => request("POST", path, { body }),
    put: (path, body) => request("PUT", path, { body }),
    patch: (path, body) => request("PATCH", path, { body }),
    delete: (path) => request("DELETE", path)
};
