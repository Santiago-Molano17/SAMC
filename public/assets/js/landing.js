import { html, mount, $ } from "./core/dom.js";
import { api } from "./core/api.js";
import { hydrateIcons, setupThemeToggle } from "./auth/common.js";

hydrateIcons();
setupThemeToggle();

// Si ya hay sesión, los botones llevan directo a la aplicación
api.get("/auth/me").then(() => {
    $('[data-slot="login-link"]').textContent = "Ir al panel";
    $('[data-slot="login-link"]').href = "/app";
    ["cta-link", "hero-cta", "band-cta"].forEach((slot) => { $(`[data-slot="${slot}"]`).href = "/app#/analyze"; });
}).catch(() => {});

// Consola de demostración que simula un análisis paso a paso
const LINES = [
    ["#94a3b8", "›", "Calculando SHA-256…", "9f86d081884c7d65…"],
    ["#22d3ee", "›", "Tipo real:", "Ejecutable de Windows (PE32)"],
    ["#f43f5e", "!", "Extensión declarada:", ".pdf.exe — doble extensión"],
    ["#f59e0b", "!", "Regla:", "Persistencia en registro (T1547.001)"],
    ["#f59e0b", "!", "Regla:", "Descarga de archivos remotos (T1105)"],
    ["#22d3ee", "›", "VirusTotal:", "48 / 72 motores lo detectan"],
    ["#22d3ee", "›", "MalwareBazaar:", "Familia AgentTesla"]
];

function play() {
    const consoleEl = $('[data-slot="console"]');
    if (!consoleEl) return;
    mount(consoleEl, html`
        ${LINES.map(([color, mark, label, value], i) => html`
            <div class="console__line" style="animation-delay:${i * 450}ms">
                <b style="color:${color}">${mark}</b><span class="muted">${label}</span><b>${value}</b>
            </div>`)}
        <div class="console__result" style="animation-delay:${LINES.length * 450 + 200}ms">
            <div><div class="strong">Veredicto: MALICIOSO</div><div class="muted small">Confianza 99% · 4 técnicas ATT&CK</div></div>
            <div class="console__score">94</div>
        </div>
    `);
}

play();
setInterval(play, 9000);
