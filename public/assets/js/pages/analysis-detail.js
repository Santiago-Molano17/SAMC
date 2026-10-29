import { html, mount, $, onAction, animateCounters, copyText, downloadBlob, formData, showFieldErrors } from "../core/dom.js";
import { api, download } from "../core/api.js";
import { session } from "../core/session.js";
import { queryParams } from "../core/router.js";
import {
    VERDICT, SEVERITY, ENGINE_STATUS, IOC_TYPE, CATEGORY, formatBytes, formatDate, formatDuration, formatNumber
} from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { openModal } from "../ui/modal.js";
import {
    verdictBadge, statusBadge, severityBadge, gauge, animateGauges, emptyState, pageLoader, personCell, avatar, relative, caseStatusBadge
} from "../ui/components.js";
import { createChart, axis, areaGradient } from "../ui/charts.js";
import { setTitle } from "../layout/shell.js";

const ENGINE_ICONS = { sacm_static: "fingerprint", sacm_rules: "target", virustotal: "shield", malwarebazaar: "bug", circl_hashlookup: "database", urlhaus: "globe" };
const SOURCE_NAMES = { sacm_static: "Estático", sacm_rules: "Reglas", virustotal: "VirusTotal", malwarebazaar: "MalwareBazaar", circl_hashlookup: "CIRCL", urlhaus: "URLhaus" };

function engineCard(e) {
    const ratio = e.total ? html`<div class="engine-card__score">${e.detections ?? 0}<small> / ${e.total}</small></div>` : "";
    return html`
        <div class="engine-card engine-card--${e.status === "ok" ? e.verdict : "unknown"}">
            <div class="engine-card__head">
                <span class="row" style="gap:10px">
                    <span class="engine-item__logo">${icon(ENGINE_ICONS[e.engine] || "shield")}</span>
                    <span class="engine-card__name">${e.name}</span>
                </span>
                ${e.status === "ok" ? verdictBadge(e.verdict === "unknown" ? "pending" : e.verdict) : html`<span class="badge badge--${e.status === "error" ? "danger" : "pending"}">${ENGINE_STATUS[e.status]}</span>`}
            </div>
            ${ratio}
            <p class="muted small">${e.summary || "—"}</p>
            <div class="row row--between small subtle">
                <span>${e.durationMs !== null && e.durationMs !== undefined ? formatDuration(e.durationMs) : ""}</span>
                ${e.permalink ? html`<a href="${e.permalink}" target="_blank" rel="noopener noreferrer">Ver fuente ${icon("external", "icon--sm")}</a>` : ""}
            </div>
        </div>`;
}

function reasonsList(reasons) {
    if (!reasons.length) return emptyState({ iconName: "check-circle", title: "Sin señales de riesgo", message: "Ningún motor encontró indicios de amenaza." });
    return html`${reasons.map((r) => {
        const negative = typeof r.impact === "number" && r.impact < 0;
        const impact = typeof r.impact === "number" ? `${r.impact > 0 ? "+" : ""}${r.impact}` : r.impact;
        return html`<div class="reason">
            <span class="reason__impact ${negative ? "reason__impact--negative" : ""}">${impact}</span>
            <span>${r.label}</span>
            <span class="reason__source">${SOURCE_NAMES[r.source] || r.source}</span>
        </div>`;
    })}`;
}

function attackMatrix(techniques) {
    if (!techniques.length) return emptyState({ iconName: "target", title: "Sin técnicas de ATT&CK detectadas" });
    const byTactic = {};
    for (const t of techniques) (byTactic[t.tactic] = byTactic[t.tactic] || []).push(t);
    return html`<div class="attack-matrix">${Object.entries(byTactic).map(([tactic, list]) => html`
        <div class="attack-tactic">
            <div class="attack-tactic__name">${tactic}</div>
            ${list.map((t) => html`<a class="attack-technique" href="https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/" target="_blank" rel="noopener noreferrer"><code>${t.id}</code>${t.name}</a>`)}
        </div>`)}
    </div>`;
}

function rulesList(rules) {
    if (!rules.length) return emptyState({ iconName: "target", title: "Ninguna regla de comportamiento coincidió" });
    return html`${rules.map((r) => html`
        <div class="rule rule--${r.severity}">
            <div class="row row--between row--wrap">
                <div class="strong">${r.name}</div>
                <div class="row">${severityBadge(r.severity)}<span class="badge badge--outline">${CATEGORY[r.category] || r.category}</span></div>
            </div>
            ${r.description ? html`<p class="muted small" style="margin-top:6px">${r.description}</p>` : ""}
            ${r.techniques.length ? html`<div class="chips" style="margin-top:10px">${r.techniques.map((t) => html`<span class="chip">${t}</span>`)}</div>` : ""}
            ${r.evidence.length ? html`<div class="rule__evidence">${r.evidence.map((e) => html`<code class="code" style="padding:8px 10px;max-height:none">${e.match}</code>`)}</div>` : ""}
        </div>`)}`;
}

function staticPanel(a) {
    const report = a.staticReport || {};
    const file = report.file || {};
    const pe = report.pe;
    return html`
        <div class="grid grid--2">
            <div class="stack">
                <div>
                    <h4 style="margin-bottom:10px">Huellas digitales</h4>
                    <div class="stack" style="gap:8px">${["sha256", "sha1", "md5"].map((type) => html`
                        <div class="hash">
                            <span class="hash__type">${type}</span>
                            <span class="hash__value" title="${a.hashes[type]}">${a.hashes[type]}</span>
                            <button class="btn btn--ghost btn--icon btn--sm" data-action="copy" data-value="${a.hashes[type]}" aria-label="Copiar">${icon("copy", "icon--sm")}</button>
                        </div>`)}
                    </div>
                </div>
                <div>
                    <h4 style="margin-bottom:10px">Identificación del archivo</h4>
                    <dl class="kv">
                        <dt>Tipo real</dt><dd>${file.label || "—"}</dd>
                        <dt>Extensión</dt><dd>${file.extension ? `.${file.extension}` : "(ninguna)"}</dd>
                        <dt>MIME</dt><dd class="mono">${file.mime || "—"}</dd>
                        <dt>Tamaño</dt><dd>${formatBytes(a.size)}</dd>
                        <dt>Entropía</dt><dd>${a.entropy ?? "—"} / 8</dd>
                        <dt>Macros</dt><dd>${file.hasMacros ? html`<span class="text-warning">Sí, contiene macros VBA</span>` : "No"}</dd>
                        <dt>Enmascaramiento</dt><dd>${file.mismatch ? html`<span class="text-danger">${file.mismatch.message}</span>` : file.doubleExtension ? html`<span class="text-danger">Doble extensión</span>` : html`<span class="text-success">No detectado</span>`}</dd>
                        <dt>Visto por primera vez</dt><dd>${formatDate(a.firstSeenAt)} · ${formatNumber(a.timesSeen)} envío(s)</dd>
                    </dl>
                </div>
            </div>
            <div>
                <h4 style="margin-bottom:4px">Perfil de entropía</h4>
                <p class="subtle small" style="margin-bottom:12px">Zonas cercanas a 8 indican contenido comprimido o cifrado.</p>
                <div class="chart chart--sm"><canvas id="entropy-chart"></canvas></div>
            </div>
        </div>
        ${pe?.valid ? html`
            <div class="divider"></div>
            <h4 style="margin-bottom:12px">Ejecutable de Windows (PE)</h4>
            <dl class="kv" style="margin-bottom:20px">
                <dt>Arquitectura</dt><dd>${pe.architecture} · ${pe.format}${pe.isDll ? " · DLL" : ""}</dd>
                <dt>Subsistema</dt><dd>${pe.subsystem}</dd>
                <dt>Compilado</dt><dd>${pe.compiledAt ? formatDate(pe.compiledAt) : "—"}${pe.futureTimestamp ? html` <span class="badge badge--warning">Fecha falsificada</span>` : ""}</dd>
                <dt>Punto de entrada</dt><dd class="mono">${pe.entryPoint} (${pe.entrySection || "?"})</dd>
                <dt>Empaquetadores</dt><dd>${pe.packers.length ? pe.packers.join(", ") : "Ninguno"}</dd>
                <dt>Datos extra (overlay)</dt><dd>${formatBytes(pe.overlaySize)}</dd>
            </dl>
            <div class="table-wrap card" style="margin-bottom:20px"><table class="table">
                <thead><tr><th>Sección</th><th class="num">Tamaño</th><th class="num">Entropía</th><th>Permisos</th></tr></thead>
                <tbody>${pe.sections.map((s) => html`<tr>
                    <td class="mono">${s.name || "(sin nombre)"} ${s.packer ? html`<span class="badge badge--warning">${s.packer}</span>` : ""}</td>
                    <td class="num">${formatBytes(s.rawSize)}</td>
                    <td class="num ${s.entropy > 7.2 ? "text-danger" : ""}">${s.entropy}</td>
                    <td class="mono">${s.readable ? "R" : "-"}${s.writable ? "W" : "-"}${s.executable ? "X" : "-"} ${s.writable && s.executable ? html`<span class="badge badge--danger">W+X</span>` : ""}</td>
                </tr>`)}</tbody>
            </table></div>
            <h4 style="margin-bottom:10px">Importaciones (${formatNumber(pe.importCount)})</h4>
            <div class="stack" style="gap:10px">${pe.imports.slice(0, 30).map((lib) => html`
                <details class="card" style="padding:10px 14px">
                    <summary class="strong mono" style="cursor:pointer">${lib.library} <span class="subtle">(${lib.functions.length})</span></summary>
                    <div class="chips" style="margin-top:10px">${lib.functions.slice(0, 120).map((f) => html`<span class="chip">${f}</span>`)}</div>
                </details>`)}
            </div>` : ""}
    `;
}

function iocPanel(indicators) {
    if (!indicators.length) return emptyState({ iconName: "radar", title: "No se extrajeron indicadores", message: "El archivo no contiene URLs, dominios, IP ni rutas sospechosas." });
    return html`<div class="table-wrap"><table class="table">
        <thead><tr><th>Tipo</th><th>Valor</th><th>Reputación</th><th></th></tr></thead>
        <tbody>${indicators.map((i) => html`<tr>
            <td><span class="badge badge--outline">${IOC_TYPE[i.type]}</span></td>
            <td class="mono break">${i.value}</td>
            <td>${i.isMalicious ? html`<span class="badge badge--malicious">${icon("alert-octagon", "icon--sm")} Malicioso (${i.source})</span>` : html`<span class="subtle small">Sin reportes</span>`}</td>
            <td><button class="btn btn--ghost btn--icon btn--sm" data-action="copy" data-value="${i.value}" aria-label="Copiar">${icon("copy", "icon--sm")}</button></td>
        </tr>`)}</tbody>
    </table></div>`;
}

function stringsPanel(strings) {
    if (!strings?.sample?.length) return emptyState({ iconName: "terminal", title: "Sin cadenas legibles" });
    return html`
        <div class="row row--between row--wrap" style="margin-bottom:12px">
            <span class="muted small">${formatNumber(strings.total)} cadenas encontradas · se muestran las ${strings.sample.length} más relevantes</span>
            <div class="input-group" style="width:260px">${icon("filter")}<input class="input" data-slot="strings-filter" placeholder="Filtrar cadenas…"></div>
        </div>
        <pre class="code" data-slot="strings">${strings.sample.join("\n")}</pre>`;
}

function enginesDetail(engines) {
    const vt = engines.find((e) => e.engine === "virustotal" && e.status === "ok");
    const mb = engines.find((e) => e.engine === "malwarebazaar" && e.status === "ok");
    const urlhaus = engines.find((e) => e.engine === "urlhaus" && e.status === "ok");
    const circl = engines.find((e) => e.engine === "circl_hashlookup" && e.status === "ok");
    return html`
        <div class="engines-grid">${engines.map(engineCard)}</div>
        ${vt?.details?.detectionsByEngine?.length ? html`
            <h4 style="margin:24px 0 12px">Detecciones en VirusTotal</h4>
            <div class="table-wrap card"><table class="table">
                <thead><tr><th>Antivirus</th><th>Resultado</th></tr></thead>
                <tbody>${vt.details.detectionsByEngine.map((d) => html`<tr><td class="strong">${d.engine}</td><td class="mono text-danger">${d.result || d.category}</td></tr>`)}</tbody>
            </table></div>` : ""}
        ${mb ? html`
            <h4 style="margin:24px 0 12px">Ficha de MalwareBazaar</h4>
            <dl class="kv card card--pad">
                <dt>Firma</dt><dd>${mb.details.signature || "—"}</dd>
                <dt>Nombre original</dt><dd class="mono">${mb.details.fileName || "—"}</dd>
                <dt>Primera vez visto</dt><dd>${mb.details.firstSeen || "—"}</dd>
                <dt>Etiquetas</dt><dd><div class="chips">${(mb.details.tags || []).map((t) => html`<span class="chip">${t}</span>`)}</div></dd>
                <dt>Método de entrega</dt><dd>${mb.details.deliveryMethod || "—"}</dd>
            </dl>` : ""}
        ${circl ? html`
            <h4 style="margin:24px 0 12px">CIRCL hashlookup</h4>
            <dl class="kv card card--pad">
                <dt>Producto</dt><dd>${circl.details.product || "—"}</dd>
                <dt>Nombre conocido</dt><dd class="mono">${circl.details.fileName || "—"}</dd>
                <dt>Fuente</dt><dd>${circl.details.source || "—"}</dd>
                <dt>Confianza</dt><dd>${circl.details.trust}/100</dd>
            </dl>` : ""}
        ${urlhaus?.details?.hosts?.length ? html`
            <h4 style="margin:24px 0 12px">Reputación de dominios (URLhaus)</h4>
            <div class="table-wrap card"><table class="table">
                <thead><tr><th>Host</th><th>Estado</th><th>Amenazas</th></tr></thead>
                <tbody>${urlhaus.details.hosts.map((h) => html`<tr>
                    <td class="mono">${h.host}</td>
                    <td>${h.listed ? html`<span class="badge badge--malicious">${h.urlCount} URL maliciosas</span>` : html`<span class="badge badge--clean">Sin reportes</span>`}</td>
                    <td>${h.threats.join(", ") || "—"}</td>
                </tr>`)}</tbody>
            </table></div>` : ""}
    `;
}

function reviewPanel(a) {
    const canReview = session.can("ANALYST") && a.status === "completed";
    return html`
        <div class="grid ${canReview ? "grid--2" : ""}">
            ${canReview ? html`
                <form class="form card card--pad" data-slot="review-form">
                    <h4>Registrar veredicto del analista</h4>
                    <p class="muted small">Tu decisión reemplaza al veredicto automático y queda en el historial.</p>
                    <div class="field">
                        <span class="field__label">Veredicto</span>
                        <div class="segmented" data-slot="verdict-picker">
                            ${["malicious", "suspicious", "clean"].map((v) => html`<button type="button" data-verdict="${v}" class="${(a.reviewedVerdict || a.verdict) === v ? "is-active" : ""}">${VERDICT[v].label}</button>`)}
                        </div>
                        <input type="hidden" name="verdict" value="${a.reviewedVerdict || a.verdict}">
                    </div>
                    <label class="field">
                        <span class="field__label">Justificación</span>
                        <textarea class="textarea" name="notes" placeholder="Qué revisaste y por qué llegaste a esta conclusión…" required minlength="10"></textarea>
                    </label>
                    <button class="btn btn--primary" type="submit">${icon("check")} Guardar revisión</button>
                </form>` : ""}
            <div>
                <h4 style="margin-bottom:16px">Historial de revisiones</h4>
                ${a.reviews.length ? html`<div class="timeline">${a.reviews.map((r) => html`
                    <div class="timeline__item">
                        <div class="timeline__meta">${personCell(r.analyst)} · ${relative(r.createdAt)} · ${verdictBadge(r.verdict)}</div>
                        <div class="timeline__body">${r.notes}</div>
                    </div>`)}</div>`
                    : html`<p class="muted">Aún ningún analista ha revisado este análisis.</p>`}
            </div>
        </div>`;
}

const TABS = [
    { id: "summary", label: "Resumen", iconName: "gauge" },
    { id: "engines", label: "Motores", iconName: "layers" },
    { id: "behavior", label: "Comportamiento", iconName: "target" },
    { id: "static", label: "Análisis estático", iconName: "fingerprint" },
    { id: "iocs", label: "Indicadores", iconName: "radar" },
    { id: "strings", label: "Cadenas", iconName: "terminal" },
    { id: "review", label: "Revisión", iconName: "check-square" }
];

export async function render(el, { id }) {
    mount(el, pageLoader());
    let analysis = (await api.get(`/analyses/${id}`)).analysis;
    let tab = queryParams().review ? "review" : "summary";
    let poll = null;

    function counts(a) {
        return {
            engines: a.engines.filter((e) => e.status === "ok" && ["malicious", "suspicious"].includes(e.verdict)).length,
            behavior: a.rules.length,
            iocs: a.indicators.length,
            review: a.reviews.length
        };
    }

    function renderPage() {
        const a = analysis;
        setTitle(a.originalName, "Análisis");
        const verdict = a.status === "completed" ? a.finalVerdict : "pending";
        const c = counts(a);
        const isAnalyst = session.can("ANALYST");

        mount(el, html`
            <div class="row row--between row--wrap reveal" style="margin-bottom:20px">
                <a class="btn btn--ghost btn--sm" href="#/analyses">${icon("arrow-left", "icon--sm")} Volver</a>
                <div class="row row--wrap">
                    ${isAnalyst ? html`
                        <button class="btn btn--sm" data-action="add-case">${icon("briefcase", "icon--sm")} Agregar a caso</button>
                        <button class="btn btn--sm" data-action="reanalyze" ${["queued", "running"].includes(a.status) ? "disabled" : ""}>${icon("refresh", "icon--sm")} Reanalizar</button>` : ""}
                    <button class="btn btn--sm" data-action="report">${icon("download", "icon--sm")} Descargar reporte</button>
                </div>
            </div>

            <section class="card verdict-hero verdict-hero--${verdict} reveal">
                ${gauge(a.status === "completed" ? a.riskScore : 0)}
                <div style="min-width:0">
                    <div class="row row--wrap" style="margin-bottom:10px">
                        <span class="verdict-banner verdict-banner--${verdict}">${icon(VERDICT[verdict].icon, "icon--sm")} ${VERDICT[verdict].label}</span>
                        ${a.reviewedVerdict ? html`<span class="badge badge--primary">${icon("check", "icon--sm")} Confirmado por analista</span>` : ""}
                        ${a.status !== "completed" ? statusBadge(a.status) : ""}
                    </div>
                    <h2 class="verdict-hero__title">${a.originalName}</h2>
                    ${a.threatFamily ? html`<div style="margin-top:8px"><span class="chip">${icon("bug", "icon--sm")} ${a.threatFamily}</span> ${a.threatCategory ? html`<span class="badge badge--outline">${CATEGORY[a.threatCategory] || a.threatCategory}</span>` : ""}</div>` : ""}
                    <div class="verdict-hero__meta">
                        <span>${icon("file", "icon--sm")} ${a.staticReport?.file?.label || a.fileType || "—"}</span>
                        <span>${icon("database", "icon--sm")} ${formatBytes(a.size)}</span>
                        <span>${icon("calendar", "icon--sm")} ${formatDate(a.submittedAt)}</span>
                        ${a.submittedBy ? html`<span>${avatar(a.submittedBy, "xs")} ${a.submittedBy.fullName}</span>` : ""}
                    </div>
                    ${a.errorMessage ? html`<div class="alert alert--danger" style="margin-top:14px">${icon("alert-triangle")} ${a.errorMessage}</div>` : ""}
                </div>
                <div class="verdict-hero__stats">
                    <div class="mini-stat"><div class="mini-stat__label">Confianza</div><div class="mini-stat__value">${a.confidence}%</div></div>
                    <div class="mini-stat"><div class="mini-stat__label">Motores</div><div class="mini-stat__value">${c.engines}/${a.engines.length}</div></div>
                    <div class="mini-stat"><div class="mini-stat__label">Reglas</div><div class="mini-stat__value">${a.rules.length}</div></div>
                    <div class="mini-stat"><div class="mini-stat__label">ATT&CK</div><div class="mini-stat__value">${a.techniques.length}</div></div>
                </div>
            </section>

            ${a.cases?.length ? html`<div class="row row--wrap reveal" style="margin-top:14px">
                <span class="subtle small">En casos:</span>
                ${a.cases.map((cs) => html`<a class="chip" href="#/cases/${cs.id}">${cs.code} · ${cs.title} ${caseStatusBadge(cs.status)}</a>`)}
            </div>` : ""}

            <section class="card reveal" style="margin-top:20px">
                <div class="tabs" role="tablist">
                    ${TABS.map((t) => html`<button class="tab ${tab === t.id ? "is-active" : ""}" data-action="tab" data-tab="${t.id}" role="tab">
                        ${icon(t.iconName, "icon--sm")} ${t.label} ${c[t.id] ? html`<span class="tab__count">${c[t.id]}</span>` : ""}
                    </button>`)}
                </div>
                <div class="card__body tab-panel" data-slot="panel"></div>
            </section>
        `);

        animateGauges(el);
        animateCounters(el);
        renderTab();
    }

    function renderTab() {
        const a = analysis;
        const panel = $('[data-slot="panel"]', el);
        if (!panel) return;
        panel.classList.remove("tab-panel");
        void panel.offsetWidth;
        panel.classList.add("tab-panel");

        if (["queued", "running"].includes(a.status) && tab !== "review") {
            mount(panel, html`<div class="empty"><div class="spinner"></div><div class="empty__title">Análisis en curso…</div><p>Los resultados aparecerán automáticamente.</p></div>`);
            return;
        }

        const views = {
            summary: () => html`
                <div class="grid grid--2">
                    <div>
                        <h4 style="margin-bottom:6px">¿Por qué este puntaje?</h4>
                        <p class="subtle small" style="margin-bottom:10px">Cada señal suma o resta puntos; "≥" fija un mínimo por evidencia fuerte.</p>
                        ${reasonsList(a.scoreBreakdown)}
                    </div>
                    <div>
                        <h4 style="margin-bottom:12px">Técnicas MITRE ATT&CK</h4>
                        ${attackMatrix(a.techniques)}
                    </div>
                </div>
                <div class="divider"></div>
                <h4 style="margin-bottom:12px">Resultado por motor</h4>
                <div class="engines-grid">${a.engines.map(engineCard)}</div>
                ${a.related.length ? html`
                    <div class="divider"></div>
                    <h4 style="margin-bottom:12px">Otros envíos del mismo archivo</h4>
                    <div class="stack" style="gap:8px">${a.related.map((r) => html`
                        <a class="row row--between card" style="padding:10px 14px;color:inherit" href="#/analyses/${r.id}">
                            <span class="truncate">${r.originalName}</span>
                            <span class="row">${verdictBadge(r.verdict)} <span class="subtle small">${relative(r.submittedAt)}</span></span>
                        </a>`)}</div>` : ""}
            `,
            engines: () => enginesDetail(a.engines),
            behavior: () => html`
                <h4 style="margin-bottom:12px">Reglas que coincidieron</h4>
                ${rulesList(a.rules)}
                <div class="divider"></div>
                <h4 style="margin-bottom:12px">Matriz MITRE ATT&CK</h4>
                ${attackMatrix(a.techniques)}`,
            static: () => staticPanel(a),
            iocs: () => iocPanel(a.indicators),
            strings: () => stringsPanel(a.staticReport?.strings),
            review: () => reviewPanel(a)
        };

        mount(panel, views[tab]());

        if (tab === "static") {
            const profile = a.staticReport?.entropy?.profile || [];
            createChart($("#entropy-chart", panel), () => ({
                type: "line",
                data: {
                    labels: profile.map((_, i) => `${Math.round((i / Math.max(1, profile.length)) * 100)}%`),
                    datasets: [{
                        label: "Entropía",
                        data: profile,
                        borderColor: "#8b5cf6",
                        backgroundColor: areaGradient("#8b5cf6"),
                        fill: true,
                        tension: 0.35,
                        pointRadius: 0,
                        borderWidth: 2
                    }]
                },
                options: {
                    plugins: { legend: { display: false } },
                    scales: { x: axis({ grid: false, ticks: { maxTicksLimit: 6 } }), y: axis({ ticks: { stepSize: 2 } }) },
                    elements: { line: { capBezierPoints: true } }
                }
            }));
            const chart = $("#entropy-chart", panel);
            if (chart) chart.closest(".chart").setAttribute("aria-label", "Entropía por bloque del archivo");
        }

        if (tab === "strings") {
            const input = $('[data-slot="strings-filter"]', panel);
            const pre = $('[data-slot="strings"]', panel);
            input?.addEventListener("input", () => {
                const term = input.value.toLowerCase();
                pre.textContent = a.staticReport.strings.sample.filter((s) => s.toLowerCase().includes(term)).join("\n");
            });
        }

        if (tab === "review") {
            const form = $('[data-slot="review-form"]', panel);
            if (!form) return;
            form.querySelectorAll("[data-verdict]").forEach((btn) => btn.addEventListener("click", () => {
                form.querySelectorAll("[data-verdict]").forEach((b) => b.classList.toggle("is-active", b === btn));
                form.elements.verdict.value = btn.dataset.verdict;
            }));
            form.addEventListener("submit", async (event) => {
                event.preventDefault();
                const button = form.querySelector('[type="submit"]');
                button.classList.add("is-loading");
                try {
                    const result = await api.post(`/analyses/${a.id}/reviews`, formData(form));
                    analysis = result.analysis;
                    toast.success("El veredicto quedó registrado", "Revisión guardada");
                    renderPage();
                } catch (error) {
                    showFieldErrors(form, error.fields);
                    toast.error(error.message);
                } finally {
                    button.classList.remove("is-loading");
                }
            });
        }
    }

    function startPolling() {
        if (poll || !["queued", "running"].includes(analysis.status)) return;
        poll = setInterval(async () => {
            const status = await api.get(`/analyses/${id}/status`).catch(() => null);
            if (status && !["queued", "running"].includes(status.status)) {
                clearInterval(poll);
                poll = null;
                analysis = (await api.get(`/analyses/${id}`)).analysis;
                renderPage();
            }
        }, 1500);
    }

    async function addToCase() {
        const { items } = await api.get("/cases", { status: "active", pageSize: 50 });
        await openModal({
            title: "Agregar a un caso",
            subtitle: "Vincula este análisis a una investigación existente o crea una nueva.",
            content: html`
                <div class="stack" style="gap:8px">
                    ${items.map((cs) => html`<button class="btn btn--block" style="justify-content:space-between;height:auto;padding:12px 14px" data-case="${cs.id}">
                        <span style="text-align:left"><span class="mono subtle small">${cs.code}</span><br><span class="strong">${cs.title}</span></span>
                        ${caseStatusBadge(cs.status)}
                    </button>`)}
                    ${items.length ? "" : html`<p class="muted">No hay casos activos.</p>`}
                </div>`,
            footer: html`<button class="btn" data-close>Cancelar</button><a class="btn btn--primary" href="#/cases?new=${analysis.id}" data-close>${icon("plus", "icon--sm")} Crear caso nuevo</a>`,
            onOpen: (modal, close) => {
                modal.querySelectorAll("[data-case]").forEach((btn) => btn.addEventListener("click", async () => {
                    try {
                        await api.post(`/cases/${btn.dataset.case}/analyses`, { analysisId: analysis.id });
                        toast.success("El análisis quedó vinculado al caso");
                        analysis = (await api.get(`/analyses/${id}`)).analysis;
                        renderPage();
                        close(true);
                    } catch (error) {
                        toast.error(error.message);
                    }
                }));
            }
        });
    }

    const off = onAction(el, {
        tab: (button) => {
            tab = button.dataset.tab;
            el.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t === button));
            renderTab();
        },
        copy: async (button) => {
            if (await copyText(button.dataset.value)) toast.success("Copiado al portapapeles");
        },
        report: async () => {
            try {
                const { blob, name } = await download(`/analyses/${id}/report`);
                downloadBlob(blob, name);
            } catch (error) {
                toast.error(error.message);
            }
        },
        reanalyze: async () => {
            try {
                await api.post(`/analyses/${id}/reanalyze`);
                toast.info("Se volverá a consultar cada motor", "Reanálisis en curso");
                analysis = (await api.get(`/analyses/${id}`)).analysis;
                renderPage();
                startPolling();
            } catch (error) {
                toast.error(error.message);
            }
        },
        "add-case": () => addToCase().catch((error) => toast.error(error.message))
    });

    renderPage();
    startPolling();

    return () => {
        off();
        if (poll) clearInterval(poll);
    };
}
