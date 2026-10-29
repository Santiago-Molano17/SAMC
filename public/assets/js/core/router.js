/**
 * Enrutador por hash (#/ruta/:param) con control de acceso por rol.
 */
import { session } from "./session.js";

const routes = [];
let notFound = null;
let current = { cleanup: null };
let renderFn = null;

/** pattern: "/analyses/:id" */
export function route(pattern, options) {
    const keys = [];
    const regex = new RegExp(`^${pattern.replace(/:(\w+)/g, (_, key) => {
        keys.push(key);
        return "([^/]+)";
    })}/?$`);
    routes.push({ pattern, regex, keys, ...options });
}

export const setNotFound = (handler) => { notFound = handler; };

export function currentPath() {
    const hash = location.hash.replace(/^#/, "") || "/";
    return hash.split("?")[0];
}

export function queryParams() {
    const query = location.hash.split("?")[1] || "";
    return Object.fromEntries(new URLSearchParams(query));
}

/** Actualiza los parámetros de la URL sin volver a renderizar la página */
export function setQueryParams(params, { replace = true } = {}) {
    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null && value !== "") search.set(key, value);
    }
    const query = search.toString();
    const hash = `#${currentPath()}${query ? `?${query}` : ""}`;
    if (replace) history.replaceState(null, "", hash);
    else history.pushState(null, "", hash);
}

export function navigate(path) {
    location.hash = path;
}

function match(path) {
    for (const r of routes) {
        const m = r.regex.exec(path);
        if (m) {
            const params = Object.fromEntries(r.keys.map((key, i) => [key, decodeURIComponent(m[i + 1])]));
            return { route: r, params };
        }
    }
    return null;
}

async function resolve() {
    const path = currentPath();
    const found = match(path);

    if (typeof current.cleanup === "function") current.cleanup();
    current = { cleanup: null };

    if (!found) {
        renderFn({ route: notFound, params: {} });
        return;
    }
    if (found.route.minRole && !session.can(found.route.minRole)) {
        renderFn({ route: { ...notFound, forbidden: true }, params: {} });
        return;
    }
    const cleanup = await renderFn(found);
    current.cleanup = cleanup;
}

export function startRouter(render) {
    renderFn = render;
    window.addEventListener("hashchange", resolve);
    if (!location.hash) history.replaceState(null, "", "#/");
    resolve();
}

export function routesFor(user) {
    return routes.filter((r) => r.nav && (!r.minRole || session.can(r.minRole)));
}
