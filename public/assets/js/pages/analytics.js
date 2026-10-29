import { html, mount, $, onAction, animateCounters, downloadBlob } from "../core/dom.js";
import { api, download } from "../core/api.js";
import { queryParams, setQueryParams } from "../core/router.js";
import { formatNumber, formatDuration, CATEGORY, IOC_TYPE } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { kpiCard, trend, barList, emptyState, pageLoader, severityBadge } from "../ui/components.js";
import { createChart, destroyCharts, axis, areaGradient, PALETTE, VERDICT_COLORS } from "../ui/charts.js";

const PRESETS = [
    { id: "7", label: "7 días" },
    { id: "30", label: "30 días" },
    { id: "90", label: "90 días" }
];

const WEEKDAYS = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"];
const ENGINE_NAMES = { sacm_static: "Estático SACM", sacm_rules: "Reglas SACM", virustotal: "VirusTotal", malwarebazaar: "MalwareBazaar", circl_hashlookup: "CIRCL", urlhaus: "URLhaus" };

const isoDay = (date) => date.toISOString().slice(0, 10);

function chartCard({ id, title, subtitle, iconName, size = "", span = false }) {
    return html`<section class="card ${span ? "span-2" : ""}">
        <div class="card__header">
            <div>
                <div class="card__title">${icon(iconName)} ${title}</div>
                ${subtitle ? html`<div class="card__subtitle">${subtitle}</div>` : ""}
            </div>
            <button class="btn btn--ghost btn--icon btn--sm tooltip" data-action="png" data-chart="${id}" data-tip="Descargar como imagen" aria-label="Descargar gráfica">${icon("download", "icon--sm")}</button>
        </div>
        <div class="card__body"><div class="chart ${size}"><canvas id="${id}"></canvas></div></div>
    </section>`;
}

function heatmap(cells) {
    const max = Math.max(1, ...cells.map((c) => c.total));
    const grid = Array.from({ length: 7 }, () => Array(24).fill(0));
    // Las horas llegan en UTC; se muestran en la hora local del navegador
    const offset = -new Date().getTimezoneOffset() / 60;
    for (const c of cells) {
        let hour = c.hour + offset;
        let day = c.weekday;
        if (hour < 0) { hour += 24; day = (day + 6) % 7; }
        if (hour >= 24) { hour -= 24; day = (day + 1) % 7; }
        grid[day][Math.round(hour) % 24] += c.total;
    }
    return html`<div class="heatmap">
        <span></span>${Array.from({ length: 24 }, (_, h) => html`<span class="heatmap__label" style="justify-content:center">${h % 3 === 0 ? h : ""}</span>`)}
        ${grid.map((hours, day) => html`
            <span class="heatmap__label">${WEEKDAYS[day]}</span>
            ${hours.map((total, hour) => html`<span class="heatmap__cell tooltip" data-tip="${WEEKDAYS[day]} ${hour}:00 · ${total} análisis" style="opacity:${total ? 0.15 + (total / max) * 0.85 : 0.05}"></span>`)}
        `)}
    </div>`;
}

export async function render(el) {
    const initial = queryParams();
    const state = {
        preset: initial.preset || (initial.from ? "custom" : "30"),
        from: initial.from || "",
        to: initial.to || ""
    };

    function range() {
        if (state.preset === "custom" && state.from && state.to) return { from: state.from, to: state.to };
        const days = Number(state.preset) || 30;
        const to = new Date();
        const from = new Date(Date.now() - (days - 1) * 86400000);
        return { from: isoDay(from), to: isoDay(to) };
    }

    mount(el, html`
        <div class="page-header reveal">
            <div>
                <h2>Analítica de amenazas</h2>
                <p class="page-header__subtitle">Tendencias, familias, técnicas de ATT&CK y desempeño de los motores.</p>
            </div>
            <div class="page-header__actions">
                <div class="segmented" data-slot="presets">
                    ${PRESETS.map((p) => html`<button data-action="preset" data-preset="${p.id}" class="${state.preset === p.id ? "is-active" : ""}">${p.label}</button>`)}
                </div>
                <input class="input" type="date" name="from" style="width:150px;height:36px" aria-label="Desde">
                <input class="input" type="date" name="to" style="width:150px;height:36px" aria-label="Hasta">
                <button class="btn" data-action="csv">${icon("download")} Exportar CSV</button>
            </div>
        </div>
        <div data-slot="body"></div>
    `);

    const body = $('[data-slot="body"]', el);
    const fromInput = $('[name="from"]', el);
    const toInput = $('[name="to"]', el);

    async function load() {
        destroyCharts();
        const r = range();
        fromInput.value = r.from;
        toInput.value = r.to;
        setQueryParams(state.preset === "custom" ? { from: r.from, to: r.to } : { preset: state.preset });
        el.querySelectorAll('[data-action="preset"]').forEach((b) => b.classList.toggle("is-active", b.dataset.preset === state.preset));

        mount(body, pageLoader());
        let data;
        try {
            data = await api.get("/analytics/overview", { from: r.from, to: `${r.to}T23:59:59` });
        } catch (error) {
            mount(body, emptyState({ iconName: "alert-triangle", title: "No se pudo cargar la analítica", message: error.message }));
            return;
        }
        draw(data);
    }

    function draw(d) {
        const k = d.kpis;
        const engines = d.engines.filter((e) => !["sacm_static", "sacm_rules"].includes(e.engine));

        mount(body, html`
            <div class="stack">
                <div class="grid grid--kpi reveal-stagger">
                    ${kpiCard({ label: "Análisis en el periodo", value: k.total, iconName: "layers", foot: html`${trend(d.deltas.total)} vs. periodo anterior` })}
                    ${kpiCard({ label: "Detecciones maliciosas", value: k.malicious, iconName: "alert-octagon", tone: "danger", foot: html`${trend(d.deltas.malicious)} vs. periodo anterior` })}
                    ${kpiCard({ label: "Tasa de detección", value: k.detectionRate, decimals: 1, suffix: "%", iconName: "target", tone: "warning", foot: html`${trend(d.deltas.detectionRate, { suffix: " pts" })} maliciosos + sospechosos` })}
                    ${kpiCard({ label: "Riesgo promedio", value: k.avgRisk, decimals: 1, iconName: "gauge", tone: "accent", foot: html`${trend(d.deltas.avgRisk)} · ${formatNumber(k.uniqueSamples)} muestras únicas` })}
                    ${kpiCard({ label: "Tiempo medio de análisis", value: Math.round(k.avgDurationMs / 100) / 10, decimals: 1, suffix: " s", iconName: "zap", tone: "success", foot: `${formatNumber(k.reviewed)} revisados por analistas` })}
                </div>

                <div class="grid grid--main-side">
                    ${chartCard({ id: "timeline", title: "Evolución diaria", subtitle: "Análisis por veredicto y riesgo promedio", iconName: "activity", size: "chart--lg" })}
                    ${chartCard({ id: "verdicts", title: "Distribución de veredictos", iconName: "shield", size: "chart--lg" })}
                </div>

                <div class="grid grid--3">
                    ${chartCard({ id: "risk", title: "Histograma de riesgo", subtitle: "Cantidad de análisis por rango de puntaje", iconName: "bar-chart" })}
                    ${chartCard({ id: "tactics", title: "Tácticas de ATT&CK", subtitle: "Frecuencia por táctica", iconName: "target" })}
                    ${chartCard({ id: "types", title: "Tipos de archivo", subtitle: "Total y maliciosos por tipo real", iconName: "file" })}
                </div>

                <div class="grid grid--2">
                    <section class="card">
                        <div class="card__header"><div class="card__title">${icon("bug")} Familias de malware</div></div>
                        <div class="card__body">${barList(d.families, { tone: "danger", href: (f) => `#/analyses?family=${encodeURIComponent(f.label)}`, format: (v, f) => html`${formatNumber(v)} <span class="subtle small">· riesgo ${f.avgRisk}</span>` })}</div>
                    </section>
                    <section class="card">
                        <div class="card__header"><div class="card__title">${icon("target")} Técnicas más observadas</div></div>
                        <div class="card__body">${barList(d.techniques.slice(0, 8).map((t) => ({ ...t, label: `${t.id} · ${t.name}` })), { tone: "", href: (t) => `#/analyses?technique=${t.id}` })}</div>
                    </section>
                </div>

                <div class="grid grid--2">
                    <section class="card">
                        <div class="card__header">
                            <div>
                                <div class="card__title">${icon("calendar")} Mapa de calor de actividad</div>
                                <div class="card__subtitle">Envíos por día de la semana y hora (hora local)</div>
                            </div>
                        </div>
                        <div class="card__body">${heatmap(d.heatmap)}</div>
                    </section>
                    <section class="card">
                        <div class="card__header"><div class="card__title">${icon("check-square")} Calidad de la detección</div></div>
                        <div class="card__body">
                            <div class="grid" style="grid-template-columns:repeat(3,minmax(0,1fr));gap:12px">
                                <div class="mini-stat"><div class="mini-stat__label">Confirmados</div><div class="mini-stat__value text-success" data-count="${d.corrections.confirmed}">0</div></div>
                                <div class="mini-stat"><div class="mini-stat__label">Falsos positivos</div><div class="mini-stat__value text-warning" data-count="${d.corrections.falsePositives}">0</div></div>
                                <div class="mini-stat"><div class="mini-stat__label">Falsos negativos</div><div class="mini-stat__value text-danger" data-count="${d.corrections.falseNegatives}">0</div></div>
                            </div>
                            <p class="subtle small" style="margin:12px 0 16px">Comparación entre el veredicto automático y la decisión de los analistas.</p>
                            <h4 style="margin-bottom:12px">Reglas que más disparan</h4>
                            ${d.topRules.length ? html`<div class="stack" style="gap:8px">${d.topRules.slice(0, 6).map((r) => html`
                                <div class="row row--between"><span class="truncate">${r.label}</span><span class="row">${severityBadge(r.severity)}<strong>${r.total}</strong></span></div>`)}</div>`
                                : html`<p class="muted">Sin coincidencias en el periodo.</p>`}
                        </div>
                    </section>
                </div>

                <div class="grid grid--2">
                    <section class="card">
                        <div class="card__header">
                            <div class="card__title">${icon("server")} Desempeño de los motores externos</div>
                        </div>
                        <div class="card__body card__body--flush">
                            ${engines.length ? html`<div class="table-wrap"><table class="table">
                                <thead><tr><th>Motor</th><th class="num">Consultas</th><th class="num">Encontrados</th><th class="num">Maliciosos</th><th class="num">Errores</th><th class="num">Tiempo medio</th></tr></thead>
                                <tbody>${engines.map((e) => html`<tr>
                                    <td class="strong">${ENGINE_NAMES[e.engine] || e.engine}</td>
                                    <td class="num">${formatNumber(e.total)}</td>
                                    <td class="num">${formatNumber(e.ok)}</td>
                                    <td class="num text-danger">${formatNumber(e.malicious)}</td>
                                    <td class="num ${e.errors ? "text-warning" : ""}">${formatNumber(e.errors)}</td>
                                    <td class="num">${formatDuration(e.avgMs)}</td>
                                </tr>`)}</tbody>
                            </table></div>` : emptyState({ iconName: "server", title: "Sin consultas externas en el periodo", message: "Configura las API keys en Sistema para enriquecer los análisis." })}
                        </div>
                    </section>
                    <section class="card">
                        <div class="card__header">
                            <div class="card__title">${icon("radar")} Indicadores más frecuentes</div>
                            <a class="btn btn--sm" href="#/iocs">Explorar IOC ${icon("arrow-right", "icon--sm")}</a>
                        </div>
                        <div class="card__body card__body--flush">
                            ${d.topIocs.length ? html`<div class="table-wrap"><table class="table">
                                <thead><tr><th>Tipo</th><th>Valor</th><th class="num">Análisis</th></tr></thead>
                                <tbody>${d.topIocs.map((i) => html`<tr>
                                    <td><span class="badge badge--outline">${IOC_TYPE[i.type]}</span></td>
                                    <td class="mono truncate" style="max-width:300px" title="${i.value}">${i.malicious ? html`<span class="text-danger">${icon("alert-octagon", "icon--sm")}</span> ` : ""}${i.value}</td>
                                    <td class="num">${i.total}</td>
                                </tr>`)}</tbody>
                            </table></div>` : emptyState({ iconName: "radar", title: "Sin indicadores de red en el periodo" })}
                        </div>
                    </section>
                </div>

                <div class="grid grid--2">
                    ${chartCard({ id: "categories", title: "Categorías de amenaza", iconName: "layers", size: "chart--sm" })}
                    <section class="card">
                        <div class="card__header"><div class="card__title">${icon("users")} Usuarios que más envían</div></div>
                        <div class="card__body">${barList(d.topSubmitters, { format: (v, s) => html`${formatNumber(v)} <span class="small text-danger">${s.malicious ? `· ${s.malicious} maliciosos` : ""}</span>` })}</div>
                    </section>
                </div>
            </div>
        `);

        animateCounters(body);

        const labels = d.timeline.map((t) => new Date(`${t.day}T12:00:00Z`).toLocaleDateString("es-CO", { day: "2-digit", month: "short" }));
        createChart($("#timeline", body), () => ({
            data: {
                labels,
                datasets: [
                    { type: "line", label: "Maliciosos", data: d.timeline.map((t) => t.malicious), borderColor: VERDICT_COLORS.malicious, backgroundColor: areaGradient(VERDICT_COLORS.malicious), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 },
                    { type: "line", label: "Sospechosos", data: d.timeline.map((t) => t.suspicious), borderColor: VERDICT_COLORS.suspicious, backgroundColor: areaGradient(VERDICT_COLORS.suspicious), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 },
                    { type: "line", label: "Limpios", data: d.timeline.map((t) => t.clean), borderColor: VERDICT_COLORS.clean, backgroundColor: areaGradient(VERDICT_COLORS.clean), fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2 },
                    { type: "line", label: "Riesgo promedio", data: d.timeline.map((t) => t.avgRisk), borderColor: "#8b5cf6", borderDash: [6, 4], pointRadius: 0, borderWidth: 2, tension: 0.35, yAxisID: "risk", spanGaps: true }
                ]
            },
            options: {
                interaction: { mode: "index", intersect: false },
                plugins: { legend: { position: "bottom" } },
                scales: {
                    x: axis({ grid: false, ticks: { maxTicksLimit: 10 } }),
                    y: axis({ ticks: { precision: 0 } }),
                    risk: { ...axis({ grid: false }), position: "right", min: 0, max: 100 }
                }
            }
        }));

        createChart($("#verdicts", body), () => ({
            type: "doughnut",
            data: {
                labels: ["Maliciosos", "Sospechosos", "Limpios"],
                datasets: [{ data: [k.malicious, k.suspicious, k.clean], backgroundColor: [VERDICT_COLORS.malicious, VERDICT_COLORS.suspicious, VERDICT_COLORS.clean], borderWidth: 0, hoverOffset: 10, spacing: 3, borderRadius: 6 }]
            },
            options: { cutout: "68%", plugins: { legend: { position: "bottom" } } }
        }));

        createChart($("#risk", body), () => ({
            type: "bar",
            data: {
                labels: d.riskBuckets.map((b) => b.range),
                datasets: [{
                    label: "Análisis",
                    data: d.riskBuckets.map((b) => b.total),
                    backgroundColor: d.riskBuckets.map((_, i) => (i >= 7 ? VERDICT_COLORS.malicious : i >= 3 ? VERDICT_COLORS.suspicious : VERDICT_COLORS.clean)),
                    borderRadius: 6
                }]
            },
            options: { plugins: { legend: { display: false } }, scales: { x: axis({ grid: false }), y: axis({ ticks: { precision: 0 } }) } }
        }));

        createChart($("#tactics", body), () => ({
            type: "radar",
            data: {
                labels: d.tactics.map((t) => t.label),
                datasets: [{ label: "Técnicas observadas", data: d.tactics.map((t) => t.total), borderColor: "#22d3ee", backgroundColor: "rgba(34, 211, 238, 0.2)", pointBackgroundColor: "#22d3ee", borderWidth: 2 }]
            },
            options: {
                plugins: { legend: { display: false } },
                scales: { r: { beginAtZero: true, ticks: { display: false }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue("--chart-grid") }, angleLines: { color: getComputedStyle(document.documentElement).getPropertyValue("--chart-grid") }, pointLabels: { font: { size: 11 } } } }
            }
        }));

        createChart($("#types", body), () => ({
            type: "bar",
            data: {
                labels: d.fileTypes.map((t) => t.label.toUpperCase()),
                datasets: [
                    { label: "Total", data: d.fileTypes.map((t) => t.total), backgroundColor: "#3b82f6", borderRadius: 6 },
                    { label: "Maliciosos", data: d.fileTypes.map((t) => t.malicious), backgroundColor: VERDICT_COLORS.malicious, borderRadius: 6 }
                ]
            },
            options: { indexAxis: "y", plugins: { legend: { position: "bottom" } }, scales: { x: axis({ ticks: { precision: 0 } }), y: axis({ grid: false }) } }
        }));

        createChart($("#categories", body), () => ({
            type: "polarArea",
            data: {
                labels: d.categories.map((c) => CATEGORY[c.label] || c.label),
                datasets: [{ data: d.categories.map((c) => c.total), backgroundColor: PALETTE.map((c) => `${c}b3`), borderWidth: 0 }]
            },
            options: { plugins: { legend: { position: "right" } }, scales: { r: { ticks: { display: false }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue("--chart-grid") } } } }
        }));
    }

    const off = onAction(el, {
        preset: (button) => {
            state.preset = button.dataset.preset;
            load();
        },
        csv: async () => {
            try {
                const r = range();
                const { blob, name } = await download("/analytics/export.csv", { from: r.from, to: `${r.to}T23:59:59` });
                downloadBlob(blob, name);
                toast.success("El archivo CSV se descargó", "Exportación lista");
            } catch (error) {
                toast.error(error.message);
            }
        },
        png: (button) => {
            const canvas = document.getElementById(button.dataset.chart);
            const chart = window.Chart?.getChart(canvas);
            if (!chart) return;
            const link = document.createElement("a");
            link.href = chart.toBase64Image("image/png", 1);
            link.download = `sacm-${button.dataset.chart}-${isoDay(new Date())}.png`;
            link.click();
        }
    });

    [fromInput, toInput].forEach((input) => input.addEventListener("change", () => {
        if (fromInput.value && toInput.value && fromInput.value <= toInput.value) {
            state.preset = "custom";
            state.from = fromInput.value;
            state.to = toInput.value;
            load();
        }
    }));

    await load();
    return () => {
        off();
        destroyCharts();
    };
}

