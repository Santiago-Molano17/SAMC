import { html, mount, $, onAction, debounce } from "../core/dom.js";
import { api } from "../core/api.js";
import { session } from "../core/session.js";
import { queryParams, setQueryParams } from "../core/router.js";
import { formatNumber } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { verdictBadge, statusBadge, riskBar, fileCell, emptyState, skeletonRows, pagination, relative, personCell } from "../ui/components.js";

/**
 * @param {{ mode?: "list" | "review" }} options
 */
export function createAnalysesPage({ mode = "list" } = {}) {
    return async function render(el) {
        const isAnalyst = session.can("ANALYST");
        const review = mode === "review";
        const initial = queryParams();
        const state = {
            q: initial.q || "",
            verdict: initial.verdict || "",
            status: initial.status || "",
            scope: initial.scope || (isAnalyst ? "all" : "mine"),
            sort: initial.sort || (review ? "risk" : "recent"),
            family: initial.family || "",
            technique: initial.technique || "",
            page: Number(initial.page) || 1
        };
        let controller = null;

        const filterChip = state.family || state.technique;

        mount(el, html`
            <div class="page-header reveal">
                <div>
                    <h2>${review ? "Cola de revisión" : isAnalyst ? "Todos los análisis" : "Mis análisis"}</h2>
                    <p class="page-header__subtitle">${review
                        ? "Archivos sospechosos o con baja confianza que necesitan la decisión de un analista."
                        : "Historial completo con búsqueda por nombre, hash o familia de malware."}</p>
                </div>
                <div class="page-header__actions">
                    <a class="btn btn--primary" href="#/analyze">${icon("upload")} Analizar archivo</a>
                </div>
            </div>

            <section class="card reveal">
                <div class="toolbar">
                    <div class="input-group search" style="flex:1">
                        ${icon("search")}
                        <input class="input" type="search" name="q" placeholder="Buscar por nombre, SHA-256, MD5 o familia…" value="${state.q}" aria-label="Buscar">
                    </div>
                    ${review ? "" : html`
                        <select class="select" name="verdict" aria-label="Veredicto">
                            <option value="">Todos los veredictos</option>
                            <option value="malicious">Maliciosos</option>
                            <option value="suspicious">Sospechosos</option>
                            <option value="clean">Limpios</option>
                        </select>
                        <select class="select" name="status" aria-label="Estado">
                            <option value="">Todos los estados</option>
                            <option value="completed">Completados</option>
                            <option value="running">En curso</option>
                            <option value="queued">En cola</option>
                            <option value="failed">Fallidos</option>
                        </select>`}
                    <select class="select" name="sort" aria-label="Orden">
                        <option value="recent">Más recientes</option>
                        <option value="risk">Mayor riesgo</option>
                        <option value="name">Nombre</option>
                    </select>
                    ${isAnalyst && !review ? html`
                        <div class="segmented" role="tablist">
                            <button data-action="scope" data-scope="all" class="${state.scope === "all" ? "is-active" : ""}">Todos</button>
                            <button data-action="scope" data-scope="mine" class="${state.scope === "mine" ? "is-active" : ""}">Míos</button>
                        </div>` : ""}
                </div>
                ${filterChip ? html`
                    <div class="toolbar" style="padding-top:10px;padding-bottom:10px">
                        <span class="subtle small">Filtro activo:</span>
                        <span class="chip">${state.family ? `Familia: ${state.family}` : `Técnica: ${state.technique}`}</span>
                        <button class="btn btn--ghost btn--sm" data-action="clear-chip">${icon("x", "icon--sm")} Quitar</button>
                    </div>` : ""}
                <div data-slot="results"></div>
            </section>
        `);

        const results = $('[data-slot="results"]', el);
        $('[name="sort"]', el).value = state.sort;
        if (!review) {
            $('[name="verdict"]', el).value = state.verdict;
            $('[name="status"]', el).value = state.status;
        }

        async function load() {
            controller?.abort();
            controller = new AbortController();
            setQueryParams({ ...state, page: state.page > 1 ? state.page : "", scope: isAnalyst && state.scope !== "all" ? state.scope : "" });

            mount(results, html`<div class="table-wrap"><table class="table"><tbody>${skeletonRows(8, 6)}</tbody></table></div>`);

            let data;
            try {
                data = await api.get("/analyses", {
                    q: state.q, verdict: state.verdict, status: state.status, sort: state.sort, page: state.page,
                    scope: isAnalyst ? state.scope : undefined, needsReview: review ? "true" : undefined,
                    family: state.family, technique: state.technique, pageSize: 15
                }, controller.signal);
            } catch (error) {
                if (error.name === "AbortError") return;
                mount(results, emptyState({ iconName: "alert-triangle", title: "No se pudieron cargar los análisis", message: error.message }));
                return;
            }

            if (!data.items.length) {
                mount(results, review
                    ? emptyState({ iconName: "check-circle", title: "¡Todo revisado!", message: "No hay análisis pendientes de revisión." })
                    : emptyState({ iconName: "search", title: "Sin resultados", message: "Prueba con otros filtros o analiza un archivo nuevo." }));
                return;
            }

            const showUser = isAnalyst && state.scope === "all";
            mount(results, html`
                <div class="table-wrap">
                    <table class="table">
                        <thead><tr>
                            <th>Archivo</th>
                            ${showUser ? html`<th>Enviado por</th>` : ""}
                            <th>Estado</th>
                            <th>Veredicto</th>
                            <th>Familia</th>
                            <th>Riesgo</th>
                            <th>Fecha</th>
                            <th></th>
                        </tr></thead>
                        <tbody class="reveal-stagger">${data.items.map((a) => html`
                            <tr data-href="#/analyses/${a.id}">
                                <td>${fileCell(a)}</td>
                                ${showUser ? html`<td>${personCell(a.submittedBy)}</td>` : ""}
                                <td>${statusBadge(a.status)}</td>
                                <td>${a.status === "completed" ? verdictBadge(a.finalVerdict, { reviewed: Boolean(a.reviewedVerdict) }) : html`<span class="subtle">—</span>`}</td>
                                <td>${a.threatFamily ? html`<span class="chip">${a.threatFamily}</span>` : html`<span class="subtle">—</span>`}</td>
                                <td>${a.status === "completed" ? riskBar(a.riskScore) : html`<span class="subtle">—</span>`}</td>
                                <td class="nowrap muted">${relative(a.submittedAt)}</td>
                                <td>${review ? html`<a class="btn btn--sm btn--primary" href="#/analyses/${a.id}?review=1">Revisar</a>` : icon("chevron-right", "subtle")}</td>
                            </tr>`)}
                        </tbody>
                    </table>
                </div>
                ${pagination(data)}
            `);

            results.querySelectorAll("tr[data-href]").forEach((row) => row.addEventListener("click", (event) => {
                if (event.target.closest("a")) return;
                location.hash = row.dataset.href;
            }));

            if (review) document.querySelector('[data-slot="title"]').textContent = `Cola de revisión (${formatNumber(data.total)})`;
        }

        const search = debounce(() => {
            state.page = 1;
            load();
        }, 350);
        $('[name="q"]', el).addEventListener("input", (event) => {
            state.q = event.target.value.trim();
            search();
        });
        el.querySelectorAll("select").forEach((select) => select.addEventListener("change", () => {
            state[select.name] = select.value;
            state.page = 1;
            load();
        }));

        const off = onAction(el, {
            page: (button) => {
                state.page = Number(button.dataset.page);
                load();
                el.scrollIntoView({ behavior: "smooth" });
            },
            scope: (button) => {
                state.scope = button.dataset.scope;
                state.page = 1;
                el.querySelectorAll('[data-action="scope"]').forEach((b) => b.classList.toggle("is-active", b === button));
                load();
            },
            "clear-chip": () => {
                state.family = "";
                state.technique = "";
                el.querySelector('[data-action="clear-chip"]')?.closest(".toolbar")?.remove();
                load();
            }
        });

        await load();
        return () => {
            off();
            controller?.abort();
        };
    };
}

export const render = createAnalysesPage();
export const renderReview = createAnalysesPage({ mode: "review" });
