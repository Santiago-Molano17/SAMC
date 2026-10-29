import { html, mount, $, onAction, formData, showFieldErrors, debounce, raw } from "../core/dom.js";
import { api } from "../core/api.js";
import { session } from "../core/session.js";
import { queryParams, navigate } from "../core/router.js";
import { CASE_STATUS, PRIORITY, formatNumber } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { openModal } from "../ui/modal.js";
import { caseStatusBadge, priorityBadge, avatar, emptyState, pageLoader, relative, riskColor } from "../ui/components.js";

const COLUMNS = ["open", "investigating", "contained", "closed"];

function caseCard(c) {
    return html`<a class="card card--interactive case-card" href="#/cases/${c.id}">
        <div class="row row--between">
            <span class="case-card__code">${c.code}</span>
            ${priorityBadge(c.priority)}
        </div>
        <div class="case-card__title">${c.title}</div>
        <div class="row row--wrap small muted">
            <span>${icon("layers", "icon--sm")} ${c.analysesCount} análisis</span>
            <span>${icon("message", "icon--sm")} ${c.notesCount}</span>
            ${c.maxRisk !== null ? html`<span style="color:${raw(riskColor(c.maxRisk))}">${icon("gauge", "icon--sm")} riesgo ${c.maxRisk}</span>` : ""}
        </div>
        <div class="case-card__foot">
            <span class="person">${c.assignedTo ? html`${avatar(c.assignedTo, "xs")} ${c.assignedTo.fullName}` : "Sin asignar"}</span>
            <span>${relative(c.updatedAt)}</span>
        </div>
    </a>`;
}

export async function openCaseForm({ analysisIds = [] } = {}) {
    const { items: staff } = await api.get("/users/staff");
    return openModal({
        title: "Nuevo caso de investigación",
        subtitle: analysisIds.length ? `Se vincularán ${analysisIds.length} análisis` : "Agrupa análisis relacionados y documenta la investigación.",
        content: html`
            <form class="form" data-slot="case-form">
                <label class="field"><span class="field__label">Título</span><input class="input" name="title" required minlength="5" maxlength="150" placeholder="Ej: Campaña de phishing con facturas falsas"></label>
                <label class="field"><span class="field__label">Descripción</span><textarea class="textarea" name="description" maxlength="2000" placeholder="Contexto, alcance y próximos pasos…"></textarea></label>
                <div class="form-grid">
                    <label class="field"><span class="field__label">Prioridad</span>
                        <select class="select" name="priority">${Object.entries(PRIORITY).reverse().map(([k, v]) => html`<option value="${k}" ${k === "medium" ? raw("selected") : ""}>${v}</option>`)}</select>
                    </label>
                    <label class="field"><span class="field__label">Responsable</span>
                        <select class="select" name="assignedTo">${staff.map((s) => html`<option value="${s.id}" ${s.id === session.user.id ? raw("selected") : ""}>${s.fullName}</option>`)}</select>
                    </label>
                </div>
            </form>`,
        footer: html`<button class="btn" data-close>Cancelar</button><button class="btn btn--primary" data-submit>${icon("plus", "icon--sm")} Crear caso</button>`,
        onOpen: (modal, close) => {
            const form = $('[data-slot="case-form"]', modal);
            const submit = async (event) => {
                event?.preventDefault();
                const button = $("[data-submit]", modal);
                button.classList.add("is-loading");
                try {
                    const result = await api.post("/cases", { ...formData(form), analysisIds });
                    toast.success(result.message);
                    close(result.case);
                } catch (error) {
                    showFieldErrors(form, error.fields);
                    toast.error(error.message);
                } finally {
                    button.classList.remove("is-loading");
                }
            };
            form.addEventListener("submit", submit);
            $("[data-submit]", modal).addEventListener("click", submit);
        }
    });
}

export async function render(el) {
    const state = { q: "", priority: "", mine: false, view: "board" };

    mount(el, html`
        <div class="page-header reveal">
            <div>
                <h2>Casos de investigación</h2>
                <p class="page-header__subtitle">Agrupa análisis relacionados, asigna responsables y documenta cada paso.</p>
            </div>
            <div class="page-header__actions">
                <button class="btn btn--primary" data-action="new">${icon("plus")} Nuevo caso</button>
            </div>
        </div>
        <div class="grid grid--kpi reveal" data-slot="counts" style="margin-bottom:20px"></div>
        <section class="card reveal" style="margin-bottom:20px">
            <div class="toolbar" style="border-bottom:none">
                <div class="input-group search" style="flex:1">${icon("search")}<input class="input" type="search" name="q" placeholder="Buscar por código, título o descripción…"></div>
                <select class="select" name="priority"><option value="">Todas las prioridades</option>${Object.entries(PRIORITY).map(([k, v]) => html`<option value="${k}">${v}</option>`)}</select>
                <button class="btn" data-action="mine">${icon("user")} Asignados a mí</button>
            </div>
        </section>
        <div data-slot="board"></div>
    `);

    const board = $('[data-slot="board"]', el);

    async function load() {
        mount(board, pageLoader());
        const data = await api.get("/cases", { q: state.q, priority: state.priority, mine: state.mine ? "true" : undefined, pageSize: 100 });

        mount($('[data-slot="counts"]', el), html`
            ${COLUMNS.map((status) => html`<div class="card kpi">
                <div class="kpi__top"><span class="kpi__label">${CASE_STATUS[status]}</span>${caseStatusBadge(status)}</div>
                <div class="kpi__value">${formatNumber(data.counts[status])}</div>
            </div>`)}`);

        if (!data.items.length) {
            mount(board, html`<div class="card">${emptyState({ iconName: "briefcase", title: "No hay casos", message: "Crea uno para empezar a documentar una investigación.", action: html`<button class="btn btn--primary" data-action="new">Nuevo caso</button>` })}</div>`);
            return;
        }

        mount(board, html`<div class="kanban">${COLUMNS.map((status) => {
            const items = data.items.filter((c) => c.status === status);
            return html`<div class="kanban__col">
                <div class="kanban__head">${caseStatusBadge(status)}<span class="subtle">${items.length}</span></div>
                <div class="stack reveal-stagger" style="gap:12px">${items.map(caseCard)}</div>
            </div>`;
        })}</div>`);
    }

    $('[name="q"]', el).addEventListener("input", debounce((event) => {
        state.q = event.target.value.trim();
        load();
    }, 350));
    $('[name="priority"]', el).addEventListener("change", (event) => {
        state.priority = event.target.value;
        load();
    });

    const off = onAction(el, {
        new: async () => {
            const created = await openCaseForm().catch((e) => toast.error(e.message));
            if (created) navigate(`/cases/${created.id}`);
        },
        mine: (button) => {
            state.mine = !state.mine;
            button.classList.toggle("btn--primary", state.mine);
            load();
        }
    });

    await load();

    // Viene de "Crear caso nuevo" desde un análisis
    const fromAnalysis = queryParams().new;
    if (fromAnalysis) {
        history.replaceState(null, "", "#/cases");
        const created = await openCaseForm({ analysisIds: [fromAnalysis] }).catch((e) => toast.error(e.message));
        if (created) navigate(`/cases/${created.id}`);
    }

    return off;
}
