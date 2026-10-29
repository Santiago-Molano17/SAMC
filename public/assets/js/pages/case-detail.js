import { html, mount, $, onAction, raw } from "../core/dom.js";
import { api } from "../core/api.js";
import { CASE_STATUS, PRIORITY, formatDate } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { confirmDialog } from "../ui/modal.js";
import { caseStatusBadge, priorityBadge, avatar, verdictBadge, riskBar, emptyState, pageLoader, relative, personCell } from "../ui/components.js";
import { setTitle } from "../layout/shell.js";

export async function render(el, { id }) {
    mount(el, pageLoader());
    const [{ case: initial }, { items: staff }] = await Promise.all([api.get(`/cases/${id}`), api.get("/users/staff")]);
    let item = initial;

    function draw() {
        setTitle(item.code, "Casos");
        mount(el, html`
            <div class="row row--between row--wrap reveal" style="margin-bottom:20px">
                <a class="btn btn--ghost btn--sm" href="#/cases">${icon("arrow-left", "icon--sm")} Casos</a>
                <div class="row">${caseStatusBadge(item.status)} ${priorityBadge(item.priority)}</div>
            </div>

            <section class="card card--pad card--glow reveal">
                <div class="mono subtle">${item.code}</div>
                <h2 style="margin-top:6px;font-size:24px">${item.title}</h2>
                ${item.description ? html`<p class="muted" style="margin-top:10px;white-space:pre-wrap">${item.description}</p>` : ""}
                <div class="row row--wrap small muted" style="margin-top:16px;gap:20px">
                    <span>${icon("user", "icon--sm")} Creado por ${item.createdBy?.fullName || "—"}</span>
                    <span>${icon("calendar", "icon--sm")} ${formatDate(item.createdAt)}</span>
                    <span>${icon("clock", "icon--sm")} Actualizado ${relative(item.updatedAt)}</span>
                    ${item.closedAt ? html`<span>${icon("check", "icon--sm")} Cerrado ${formatDate(item.closedAt)}</span>` : ""}
                </div>
            </section>

            <div class="grid grid--main-side" style="margin-top:20px">
                <div class="stack">
                    <section class="card reveal">
                        <div class="card__header">
                            <div class="card__title">${icon("layers")} Análisis vinculados (${item.analyses.length})</div>
                            <a class="btn btn--sm" href="#/analyses">${icon("plus", "icon--sm")} Vincular desde análisis</a>
                        </div>
                        <div class="card__body card__body--flush">
                            ${item.analyses.length ? html`<div class="table-wrap"><table class="table">
                                <thead><tr><th>Archivo</th><th>Veredicto</th><th>Familia</th><th>Riesgo</th><th></th></tr></thead>
                                <tbody>${item.analyses.map((a) => html`<tr>
                                    <td><a class="strong" href="#/analyses/${a.id}">${a.originalName}</a><div class="mono subtle small">${a.sha256.slice(0, 16)}…</div></td>
                                    <td>${verdictBadge(a.finalVerdict)}</td>
                                    <td>${a.threatFamily ? html`<span class="chip">${a.threatFamily}</span>` : "—"}</td>
                                    <td>${riskBar(a.riskScore)}</td>
                                    <td><button class="btn btn--ghost btn--icon btn--sm tooltip" data-tip="Desvincular" data-action="unlink" data-id="${a.id}" aria-label="Desvincular">${icon("x", "icon--sm")}</button></td>
                                </tr>`)}</tbody>
                            </table></div>` : emptyState({ iconName: "layers", title: "Sin análisis vinculados", message: "Desde el reporte de un análisis usa “Agregar a caso”." })}
                        </div>
                    </section>

                    <section class="card reveal">
                        <div class="card__header"><div class="card__title">${icon("message")} Bitácora de la investigación</div></div>
                        <div class="card__body">
                            <form class="form" data-slot="note-form" style="margin-bottom:24px">
                                <textarea class="textarea" name="body" placeholder="Registra hallazgos, acciones de contención o decisiones…" required minlength="2"></textarea>
                                <div class="row" style="justify-content:flex-end"><button class="btn btn--primary" type="submit">${icon("message-plus", "icon--sm")} Agregar nota</button></div>
                            </form>
                            <div class="timeline">${item.notes.map((n) => html`
                                <div class="timeline__item">
                                    <div class="timeline__meta">${personCell(n.author)} · ${relative(n.createdAt)}</div>
                                    <div class="timeline__body">${n.body}</div>
                                </div>`)}
                            </div>
                        </div>
                    </section>
                </div>

                <aside class="stack">
                    <section class="card card--pad reveal">
                        <h4 style="margin-bottom:16px">Gestión del caso</h4>
                        <form class="form" data-slot="manage">
                            <label class="field"><span class="field__label">Estado</span>
                                <select class="select" name="status">${Object.entries(CASE_STATUS).map(([k, v]) => html`<option value="${k}" ${item.status === k ? raw("selected") : ""}>${v}</option>`)}</select>
                            </label>
                            <label class="field"><span class="field__label">Prioridad</span>
                                <select class="select" name="priority">${Object.entries(PRIORITY).map(([k, v]) => html`<option value="${k}" ${item.priority === k ? raw("selected") : ""}>${v}</option>`)}</select>
                            </label>
                            <label class="field"><span class="field__label">Responsable</span>
                                <select class="select" name="assignedTo">
                                    <option value="">Sin asignar</option>
                                    ${staff.map((s) => html`<option value="${s.id}" ${item.assignedTo?.id === s.id ? raw("selected") : ""}>${s.fullName}</option>`)}
                                </select>
                            </label>
                        </form>
                        ${item.assignedTo ? html`<div class="row" style="margin-top:16px">${avatar(item.assignedTo, "sm")}<div><div class="strong">${item.assignedTo.fullName}</div><div class="subtle small">Responsable actual</div></div></div>` : ""}
                    </section>
                    ${item.status !== "closed" ? html`<button class="btn btn--block" data-action="close-case">${icon("check-circle")} Cerrar caso</button>` : ""}
                </aside>
            </div>
        `);

        $('[data-slot="manage"]', el).addEventListener("change", async (event) => {
            const { name, value } = event.target;
            await update({ [name]: value || null });
        });

        $('[data-slot="note-form"]', el).addEventListener("submit", async (event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const button = form.querySelector("button");
            button.classList.add("is-loading");
            try {
                item = (await api.post(`/cases/${id}/notes`, { body: form.elements.body.value.trim() })).case;
                toast.success("Nota agregada a la bitácora");
                draw();
            } catch (error) {
                toast.error(error.message);
            } finally {
                button.classList.remove("is-loading");
            }
        });
    }

    async function update(changes) {
        try {
            item = (await api.patch(`/cases/${id}`, changes)).case;
            toast.success("Caso actualizado");
            draw();
        } catch (error) {
            toast.error(error.message);
        }
    }

    const off = onAction(el, {
        unlink: async (button) => {
            if (!(await confirmDialog({ title: "Desvincular análisis", message: "El análisis seguirá existiendo, pero dejará de formar parte de este caso.", confirmText: "Desvincular" }))) return;
            try {
                item = (await api.delete(`/cases/${id}/analyses/${button.dataset.id}`)).case;
                draw();
            } catch (error) {
                toast.error(error.message);
            }
        },
        "close-case": async () => {
            if (await confirmDialog({ title: "Cerrar caso", message: "Se registrará el cierre en la bitácora. Podrás reabrirlo cambiando el estado.", confirmText: "Cerrar caso" })) {
                await update({ status: "closed" });
            }
        }
    });

    draw();
    return off;
}
