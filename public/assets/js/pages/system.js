import { html, mount, $, onAction } from "../core/dom.js";
import { api } from "../core/api.js";
import { session } from "../core/session.js";
import { formatBytes, formatNumber, CATEGORY } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { pageLoader, relative, severityBadge, kpiCard } from "../ui/components.js";
import { animateCounters } from "../core/dom.js";

const ICONS = { sacm_static: "fingerprint", sacm_rules: "target", virustotal: "shield", malwarebazaar: "bug", circl_hashlookup: "database", urlhaus: "globe" };
const SIGNUP = {
    virustotal: "https://www.virustotal.com/gui/join-us",
    malwarebazaar: "https://auth.abuse.ch/",
    urlhaus: "https://auth.abuse.ch/"
};

function uptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return h ? `${h} h ${m} min` : `${m} min`;
}

export async function render(el) {
    mount(el, pageLoader());
    const [data, rules] = await Promise.all([api.get("/system/overview"), api.get("/system/rules")]);
    const isSuper = session.can("SUPER_ADMIN");

    mount(el, html`
        <div class="page-header reveal">
            <div>
                <h2>Sistema e integraciones</h2>
                <p class="page-header__subtitle">Estado del servidor, servicios de inteligencia conectados y reglas de detección.</p>
            </div>
        </div>

        <div class="grid grid--kpi reveal-stagger">
            ${kpiCard({ label: "Estado", value: 100, suffix: "%", iconName: "activity", tone: "success", foot: `Activo hace ${uptime(data.health.uptimeSec)}` })}
            ${kpiCard({ label: "Latencia de la base de datos", value: data.health.dbLatencyMs, suffix: " ms", iconName: "database", foot: `Node ${data.health.node} · ${data.health.memoryMb} MB` })}
            ${kpiCard({ label: "Muestras almacenadas", value: data.storage.samples, iconName: "layers", tone: "accent", foot: formatBytes(data.storage.bytes) })}
            ${kpiCard({ label: "Cola de análisis", value: data.health.queue.pending + data.health.queue.running, iconName: "zap", tone: "warning", foot: `${data.health.queue.running} en ejecución` })}
        </div>

        <h3 style="margin:28px 0 14px">Motores e inteligencia de amenazas</h3>
        <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr))">
            ${data.integrations.map((i) => html`
                <section class="card integration card--interactive reveal">
                    <div class="integration__head">
                        <span class="integration__logo">${icon(ICONS[i.id] || "shield", "icon--lg")}</span>
                        <div style="flex:1;min-width:0">
                            <div class="strong">${i.name}</div>
                            <span class="status-dot ${i.enabled ? "status-dot--on" : "status-dot--off"}">${i.enabled ? "Activa" : "Inactiva"}</span>
                        </div>
                        <span class="badge badge--outline">${i.type === "local" ? "Local" : "Externa"}</span>
                    </div>
                    <p class="muted small">${i.description}</p>
                    <div class="row row--between small subtle">
                        <span>${formatNumber(i.usage.total)} consultas (30 días)${i.usage.errors ? html` · <span class="text-warning">${i.usage.errors} errores</span>` : ""}</span>
                        <span>${i.usage.lastUsed ? relative(i.usage.lastUsed) : ""}</span>
                    </div>
                    ${i.type === "external" ? html`<div class="row row--wrap">
                        ${i.enabled && isSuper ? html`<button class="btn btn--sm" data-action="test" data-id="${i.id}">${icon("play", "icon--sm")} Probar conexión</button>` : ""}
                        ${!i.enabled ? html`<span class="small muted">Agrega <code>${i.requiresKey}</code> al archivo <code>.env</code></span>` : ""}
                        ${!i.enabled && SIGNUP[i.id] ? html`<a class="btn btn--sm" href="${SIGNUP[i.id]}" target="_blank" rel="noopener noreferrer">Obtener API key ${icon("external", "icon--sm")}</a>` : ""}
                    </div>` : ""}
                </section>`)}
        </div>

        <section class="card reveal" style="margin-top:28px">
            <div class="card__header">
                <div>
                    <div class="card__title">${icon("target")} Reglas de detección (${rules.items.length})</div>
                    <div class="card__subtitle">${data.engine.techniques} técnicas MITRE ATT&CK catalogadas · subida máxima ${data.engine.maxUploadMb} MB · envío a VirusTotal ${data.engine.virusTotalUpload ? "activado" : "desactivado"}</div>
                </div>
            </div>
            <div class="card__body card__body--flush">
                <div class="table-wrap"><table class="table">
                    <thead><tr><th>Regla</th><th>Severidad</th><th>Categoría</th><th>ATT&CK</th><th class="num">Coincidencias</th></tr></thead>
                    <tbody>${rules.items.map((r) => html`<tr>
                        <td><div class="strong">${r.name}</div><div class="subtle small">${r.description}</div></td>
                        <td>${severityBadge(r.severity)}</td>
                        <td>${CATEGORY[r.category] || r.category}</td>
                        <td><div class="chips">${r.techniques.map((t) => html`<span class="chip">${t}</span>`)}</div></td>
                        <td class="num strong">${formatNumber(r.matches)}</td>
                    </tr>`)}</tbody>
                </table></div>
            </div>
        </section>
    `);

    animateCounters(el);

    return onAction(el, {
        test: async (button) => {
            button.classList.add("is-loading");
            try {
                const result = await api.post(`/system/integrations/${button.dataset.id}/test`);
                if (result.ok) toast.success(`${result.message} (${result.latencyMs} ms)`, "Integración operativa");
                else toast.error(result.message, "La integración falló");
            } catch (error) {
                toast.error(error.message);
            } finally {
                button.classList.remove("is-loading");
            }
        }
    });
}

