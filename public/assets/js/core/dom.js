/**
 * Utilidades de DOM y plantillas seguras.
 *
 * `html` es una plantilla etiquetada que ESCAPA automáticamente cada valor
 * interpolado. Solo lo marcado con `raw()` se inserta sin escapar.
 * Así, ningún dato que venga del servidor o del usuario puede inyectar HTML (XSS).
 */

class SafeHtml {
    constructor(value) {
        this.value = value;
    }

    toString() {
        return this.value;
    }
}

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

export function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"'`]/g, (ch) => ESCAPES[ch]);
}

export const raw = (value) => new SafeHtml(String(value ?? ""));

function render(value) {
    if (value === null || value === undefined || value === false) return "";
    if (value instanceof SafeHtml) return value.value;
    if (Array.isArray(value)) return value.map(render).join("");
    return escapeHtml(value);
}

export function html(strings, ...values) {
    let out = "";
    strings.forEach((chunk, i) => {
        out += chunk;
        if (i < values.length) out += render(values[i]);
    });
    return new SafeHtml(out);
}

/** Reemplaza el contenido de un elemento con una plantilla segura */
export function mount(element, template) {
    element.innerHTML = render(template);
    return element;
}

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

/** Delegación de eventos: data-action="nombre" en cualquier elemento */
export function onAction(root, handlers) {
    const listener = (event) => {
        const target = event.target.closest("[data-action]");
        if (!target || !root.contains(target)) return;
        const handler = handlers[target.dataset.action];
        if (handler) {
            event.preventDefault();
            handler(target, event);
        }
    };
    root.addEventListener("click", listener);
    return () => root.removeEventListener("click", listener);
}

export function debounce(fn, ms = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), ms);
    };
}

/** Lee un formulario como objeto plano (sin campos vacíos opcionales) */
export function formData(form) {
    const data = {};
    for (const [key, value] of new FormData(form).entries()) {
        if (value instanceof File) continue;
        data[key] = typeof value === "string" ? value.trim() : value;
    }
    return data;
}

/** Muestra los errores de validación del servidor junto a cada campo */
export function showFieldErrors(form, fields = {}) {
    $$(".field", form).forEach((field) => {
        field.classList.remove("has-error");
        $(".field__error", field)?.remove();
    });
    for (const [name, message] of Object.entries(fields || {})) {
        const input = form.querySelector(`[name="${CSS.escape(name)}"]`);
        const field = input?.closest(".field");
        if (!field) continue;
        field.classList.add("has-error");
        const error = document.createElement("div");
        error.className = "field__error";
        error.textContent = message;
        field.append(error);
    }
}

/** Anima un número desde 0 hasta su valor */
export function countUp(element, target, { duration = 900, decimals = 0, suffix = "" } = {}) {
    const end = Number(target) || 0;
    if (matchMedia("(prefers-reduced-motion: reduce)").matches || end === 0) {
        element.textContent = `${end.toLocaleString("es-CO", { maximumFractionDigits: decimals })}${suffix}`;
        return;
    }
    const start = performance.now();
    const step = (now) => {
        const progress = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - progress, 3);
        element.textContent = `${(end * eased).toLocaleString("es-CO", { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}${suffix}`;
        if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

export function animateCounters(root) {
    $$("[data-count]", root).forEach((el) => {
        countUp(el, el.dataset.count, { decimals: Number(el.dataset.decimals || 0), suffix: el.dataset.suffix || "" });
    });
}

export async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        return false;
    }
}

export function downloadBlob(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
