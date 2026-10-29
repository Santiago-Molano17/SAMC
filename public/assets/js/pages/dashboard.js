import { html, mount, animateCounters } from "../core/dom.js";
import { api } from "../core/api.js";
import { session } from "../core/session.js";
import { formatNumber } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { kpiCard, verdictBadge, statusBadge, riskBar, fileCell, emptyState, pageLoader, relative, barList, personCell } from "../ui/components.js";
import { createChart, axis, VERDICT_COLORS } from "../ui/charts.js";
import { setBadges } from "../layout/shell.js";

function greeting() {
    const hour = new Date().getHours();
    if (hour < 12) return "Buenos días";
    if (hour < 19) return "Buenas tardes";
    return "Buenas noches";
}

export async function render(el) {
    mount(el, pageLoader());
    const data = await api.get("/analyses/dashboard");
    const user = session.user;
    const t = data.totals;
    const isAnalyst = session.can("ANALYST");
    const firstName = user.fullName.split(" ")[0];

    if (isAnalyst) setBadges({ pendingReview: t.pendingReview, myCases: t.myCases });

    const message = isAnalyst
        ? `Hay ${formatNumber(t.pendingReview)} análisis esperando tu revisión y ${formatNumber(t.openCases)} casos abiertos.`
        : t.total
            ? `Has enviado ${formatNumber(t.total)} archivos. ${t.malicious ? `${t.malicious} resultaron maliciosos.` : "Ninguno resultó malicioso."}`
            : "Sube tu primer archivo y SACM lo revisará con su motor de reglas y servicios de inteligencia de amenazas.";

    mount(el, html`
        <div class="stack reveal-stagger">
            <section class="card welcome card--glow">
                <div>
                    <div class="welcome__eyebrow">${greeting()}, ${firstName}</div>
                    <h2>${isAnalyst ? "Centro de operaciones de seguridad" : "Tu escudo contra archivos maliciosos"}</h2>
                    <p>${message}</p>
                    <div class="welcome__actions">
                        <a class="btn btn--primary btn--lg" href="#/analyze">${icon("upload")} Analizar archivo</a>
                        ${isAnalyst
                            ? html`<a class="btn btn--lg" href="#/review">${icon("check-square")} Revisar pendientes</a>`
                            : html`<a class="btn btn--lg" href="#/analyses">${icon("list")} Ver mis análisis</a>`}
                    </div>
                </div>
                <div class="welcome__art" aria-hidden="true">
                    <span class="welcome__orbit"></span><span class="welcome__orbit"></span>
                    <div class="welcome__shield">${icon("shield-check")}</div>
                </div>
            </section>

            <div class="grid grid--kpi">
                ${kpiCard({ label: isAnalyst ? "Análisis totales" : "Mis análisis", value: t.total, iconName: "layers", foot: html`${icon("clock", "icon--sm")} ${formatNumber(t.last24h)} en las últimas 24 h` })}
                ${kpiCard({ label: "Maliciosos", value: t.malicious, iconName: "alert-octagon", tone: "danger", foot: t.total ? `${Math.round((t.malicious / t.total) * 100)}% del total` : "—" })}
                ${kpiCard({ label: "Sospechosos", value: t.suspicious, iconName: "alert-triangle", tone: "warning", foot: isAnalyst ? `${formatNumber(t.pendingReview)} sin revisar` : "Requieren atención" })}
                ${kpiCard({ label: "Riesgo promedio", value: t.avgRisk, iconName: "gauge", tone: "accent", foot: t.inProgress ? html`<span class="badge badge--info badge--dot badge--running">${t.inProgress} en curso</span>` : "Sobre 100 puntos" })}
            </div>

            <div class="grid grid--main-side">
                <section class="card">
                    <div class="card__header">
                        <div>
                            <div class="card__title">${icon("activity")} Actividad de los últimos 14 días</div>
                            <div class="card__subtitle">Análisis por veredicto final</div>
                        </div>
                    </div>
                    <div class="card__body"><div class="chart"><canvas id="activity-chart"></canvas></div></div>
                </section>

                <section class="card">
                    <div class="card__header">
                        <div class="card__title">${icon("bug")} Familias más vistas</div>
                    </div>
                    <div class="card__body">
                        ${barList(data.families, { labelKey: "family", tone: "danger", href: isAnalyst ? (f) => `#/analyses?family=${encodeURIComponent(f.family)}` : null })}
                    </div>
                </section>
            </div>

            <section class="card">
                <div class="card__header">
                    <div>
                        <div class="card__title">${icon("clock")} Análisis recientes</div>
                        <div class="card__subtitle">${isAnalyst ? "De toda la organización" : "Tus últimos envíos"}</div>
                    </div>
                    <a class="btn btn--sm" href="#/analyses">Ver todos ${icon("arrow-right", "icon--sm")}</a>
                </div>
                <div class="card__body card__body--flush">
                    ${data.recent.length ? html`
                        <div class="table-wrap"><table class="table">
                            <thead><tr><th>Archivo</th>${isAnalyst ? html`<th>Enviado por</th>` : ""}<th>Estado</th><th>Veredicto</th><th>Riesgo</th><th>Fecha</th></tr></thead>
                            <tbody>${data.recent.map((a) => html`
                                <tr data-href="#/analyses/${a.id}">
                                    <td>${fileCell(a)}</td>
                                    ${isAnalyst ? html`<td>${personCell(a.submittedBy)}</td>` : ""}
                                    <td>${statusBadge(a.status)}</td>
                                    <td>${a.status === "completed" ? verdictBadge(a.finalVerdict, { reviewed: Boolean(a.reviewedVerdict) }) : "—"}</td>
                                    <td>${a.status === "completed" ? riskBar(a.riskScore) : "—"}</td>
                                    <td class="nowrap muted">${relative(a.submittedAt)}</td>
                                </tr>`)}
                            </tbody>
                        </table></div>`
                        : emptyState({ iconName: "upload", title: "Todavía no hay análisis", message: "Sube un archivo para empezar.", action: html`<a class="btn btn--primary" href="#/analyze">Analizar archivo</a>` })}
                </div>
            </section>
        </div>
    `);

    animateCounters(el);
    el.querySelectorAll("tr[data-href]").forEach((row) => row.addEventListener("click", () => { location.hash = row.dataset.href; }));

    const days = [];
    const byDay = new Map(data.timeline.map((d) => [new Date(d.day).toISOString().slice(0, 10), d]));
    for (let i = 13; i >= 0; i--) {
        const date = new Date(Date.now() - i * 86400000);
        const key = date.toISOString().slice(0, 10);
        days.push({ label: date.toLocaleDateString("es-CO", { day: "2-digit", month: "short" }), ...(byDay.get(key) || { malicious: 0, suspicious: 0, clean: 0 }) });
    }

    createChart(el.querySelector("#activity-chart"), () => ({
        type: "bar",
        data: {
            labels: days.map((d) => d.label),
            datasets: [
                { label: "Maliciosos", data: days.map((d) => d.malicious), backgroundColor: VERDICT_COLORS.malicious, borderRadius: 6, maxBarThickness: 26 },
                { label: "Sospechosos", data: days.map((d) => d.suspicious), backgroundColor: VERDICT_COLORS.suspicious, borderRadius: 6, maxBarThickness: 26 },
                { label: "Limpios", data: days.map((d) => d.clean), backgroundColor: VERDICT_COLORS.clean, borderRadius: 6, maxBarThickness: 26 }
            ]
        },
        options: {
            interaction: { mode: "index", intersect: false },
            plugins: { legend: { position: "bottom" } },
            scales: { x: axis({ stacked: true, grid: false }), y: axis({ stacked: true, ticks: { precision: 0 } }) }
        }
    }));
}
