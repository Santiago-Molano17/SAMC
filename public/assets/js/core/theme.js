/** Tema claro / oscuro, recordado en el navegador */

const KEY = "sacm-theme";

function stored() {
    try {
        return localStorage.getItem(KEY);
    } catch {
        return null;
    }
}

export function currentTheme() {
    return document.documentElement.dataset.theme || "dark";
}

export function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try {
        localStorage.setItem(KEY, theme);
    } catch {
        // almacenamiento no disponible
    }
    window.dispatchEvent(new CustomEvent("themechange", { detail: theme }));
}

export function initTheme() {
    const preferred = stored() || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    document.documentElement.dataset.theme = preferred;
}

export function toggleTheme() {
    applyTheme(currentTheme() === "dark" ? "light" : "dark");
}
