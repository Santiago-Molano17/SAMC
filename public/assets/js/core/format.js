/** Formateadores y etiquetas en español */

const locale = "es-CO";

export const VERDICT = {
    malicious: { label: "Malicioso", icon: "alert-octagon" },
    suspicious: { label: "Sospechoso", icon: "alert-triangle" },
    clean: { label: "Limpio", icon: "check-circle" },
    pending: { label: "Pendiente", icon: "clock" },
    unknown: { label: "Sin datos", icon: "help-circle" }
};

export const STATUS = {
    queued: "En cola",
    running: "Analizando",
    completed: "Completado",
    failed: "Falló"
};

export const SEVERITY = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja" };

export const ROLE = {
    SUPER_ADMIN: "Super administrador",
    ADMIN: "Administrador",
    ANALYST: "Analista",
    USER: "Usuario"
};

export const CASE_STATUS = { open: "Abierto", investigating: "En investigación", contained: "Contenido", closed: "Cerrado" };
export const PRIORITY = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja" };

export const ENGINE_STATUS = { ok: "Respondió", not_found: "Sin registros", skipped: "Omitido", error: "Error" };

export const IOC_TYPE = {
    url: "URL",
    domain: "Dominio",
    ipv4: "IPv4",
    email: "Correo",
    registry: "Registro",
    path: "Ruta",
    bitcoin: "Bitcoin"
};

export const CATEGORY = {
    test: "Prueba", injection: "Inyección", spyware: "Espía", evasion: "Evasión", downloader: "Descargador",
    script: "Script", persistence: "Persistencia", ransomware: "Ransomware", stealer: "Robo de datos",
    worm: "Gusano", document: "Documento", discovery: "Reconocimiento", c2: "Comando y control",
    packer: "Empaquetador", miner: "Minero", backdoor: "Puerta trasera", trojan: "Troyano"
};

export const ACTION = {
    "auth.login": "Inicio de sesión",
    "auth.login_failed": "Inicio de sesión fallido",
    "auth.logout": "Cierre de sesión",
    "auth.register": "Registro",
    "profile.update": "Perfil actualizado",
    "profile.password_change": "Cambio de contraseña",
    "profile.avatar_update": "Foto actualizada",
    "profile.avatar_remove": "Foto eliminada",
    "analysis.submit": "Archivo enviado",
    "analysis.review": "Revisión de analista",
    "analysis.reanalyze": "Reanálisis",
    "analysis.export": "Reporte exportado",
    "analytics.export": "Exportación CSV",
    "case.create": "Caso creado",
    "case.update": "Caso actualizado",
    "case.note": "Nota en caso",
    "case.link_analysis": "Análisis vinculado",
    "case.unlink_analysis": "Análisis desvinculado",
    "user.create": "Usuario creado",
    "user.update": "Usuario modificado",
    "user.delete": "Usuario eliminado",
    "system.integration_test": "Prueba de integración"
};

export function formatDate(value, options = {}) {
    if (!value) return "—";
    return new Date(value).toLocaleString(locale, {
        day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", ...options
    });
}

export function formatDay(value) {
    if (!value) return "—";
    return new Date(value).toLocaleDateString(locale, { day: "2-digit", month: "short", year: "numeric" });
}

export function timeAgo(value) {
    if (!value) return "—";
    const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
    const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
    const units = [["year", 31536000], ["month", 2592000], ["week", 604800], ["day", 86400], ["hour", 3600], ["minute", 60]];
    for (const [unit, size] of units) {
        if (Math.abs(seconds) >= size) return rtf.format(-Math.round(seconds / size), unit);
    }
    return "hace un momento";
}

export function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) return `${value} B`;
    const units = ["KB", "MB", "GB"];
    let size = value / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit++;
    }
    return `${size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
}

export const formatNumber = (value, decimals = 0) =>
    (Number(value) || 0).toLocaleString(locale, { maximumFractionDigits: decimals });

export function formatDuration(ms) {
    const value = Number(ms) || 0;
    if (value < 1000) return `${value} ms`;
    if (value < 60000) return `${(value / 1000).toFixed(1)} s`;
    return `${Math.round(value / 60000)} min`;
}

export function initials(name = "") {
    return name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("") || "?";
}

export function toneFor(text = "") {
    let hash = 0;
    for (const ch of text) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    return (hash % 5) + 1;
}

export const shortHash = (hash = "") => (hash.length > 16 ? `${hash.slice(0, 10)}…${hash.slice(-6)}` : hash);
