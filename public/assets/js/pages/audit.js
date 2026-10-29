import { html, mount, $, onAction, debounce } from "../core/dom.js";
import { api } from "../core/api.js";
import { ACTION, formatDate } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { openModal } from "../ui/modal.js";
import { emptyState, skeletonRows, pagination, relative } from "../ui/components.js";

const TONE = { "auth.login_failed": "danger", "user.delete": "danger", "auth.login": "success", "analysis.review": "primary", "user.update": "warning", "profile.password_change": "warning" };

export async function render(el) {
    const state = { q: "", action: "", page: 1 };
    let lastItems = [];

    mount(el, html`
        <div class="page-header reveal">
            <div>
                <h2>Auditoría</h2>
                <p class="page-header__subtitle">Registro inalterable de quién hizo qué, cuándo y desde dónde.</p>
            </div>
        </div>
        <section class="card reveal">
            <div class="toolbar">
                <div class="input-group search" style="flex:1">${icon("search")}<input class="input" type="search" name="q" placeholder="Buscar por usuario, correo o IP…"></div>
                <select class="select" name="action"><option value="">Todas las acciones</option>${Object.entries(ACTION).map(([k, v]) => html`<option value="${k}">${v}</option>`)}</select>
            </div>
            <div class="toolbar" data-slot="actions" style="padding-top:10px;padding-bottom:10px"></div>
            <div data-slot="results"></div>
        </section>
    `);

    const results = $('[data-slot="results"]', el);

    async function load() {
        mount(results, html`<div class="table-wrap"><table class="table"><tbody>${skeletonRows(10, 5)}</tbody></table></div>`);
        const data = await api.get("/admin/audit", { ...state, pageSize: 25 });
        lastItems = data.items;

        mount($('[data-slot="actions"]', el), html`<span class="subtle small">Últimos 30 días:</span>
            ${data.actions.slice(0, 8).map((a) => html`<button class="chip" style="cursor:pointer" data-action="filter" data-value="${a.action}">${ACTION[a.action] || a.action} <strong>${a.total}</strong></button>`)}`);

        if (!data.items.length) {
            mount(results, emptyState({ iconName: "scroll", title: "Sin eventos para estos filtros" }));
            return;
        }

        mount(results, html`
            <div class="table-wrap"><table class="table">
                <thead><tr><th>Fecha</th><th>Acción</th><th>Usuario</th><th>IP</th><th>Detalle</th></tr></thead>
                <tbody>${data.items.map((l) => html`<tr>
                    <td class="nowrap"><div>${relative(l.createdAt)}</div><div class="subtle small">${formatDate(l.createdAt)}</div></td>
                    <td><span class="badge badge--${TONE[l.action] || "outline"}">${ACTION[l.action] || l.action}</span></td>
                    <td>${l.user ? html`<div class="strong">${l.user.fullName}</div><div class="subtle small">${l.user.email}</div>` : html`<span class="subtle">${l.metadata?.email || "Sistema / anónimo"}</span>`}</td>
                    <td class="mono small">${l.ip || "—"}</td>
                    <td>${l.metadata || l.entityId ? html`<button class="btn btn--sm btn--ghost" data-action="detail" data-id="${l.id}">${icon("eye", "icon--sm")} Ver</button>` : ""}</td>
                </tr>`)}</tbody>
            </table></div>
            ${pagination(data)}
        `);
    }

    $('[name="q"]', el).addEventListener("input", debounce((event) => {
        state.q = event.target.value.trim();
        state.page = 1;
        load();
    }, 350));
    $('[name="action"]', el).addEventListener("change", (event) => {
        state.action = event.target.value;
        state.page = 1;
        load();
    });

    const off = onAction(el, {
        page: (button) => {
            state.page = Number(button.dataset.page);
            load();
        },
        filter: (button) => {
            state.action = button.dataset.value;
            $('[name="action"]', el).value = state.action;
            state.page = 1;
            load();
        },
        detail: (button) => {
            const log = lastItems.find((l) => String(l.id) === button.dataset.id);
            openModal({
                title: ACTION[log.action] || log.action,
                subtitle: formatDate(log.createdAt),
                content: html`
                    <dl class="kv" style="margin-bottom:16px">
                        <dt>Entidad</dt><dd>${log.entityType || "—"} ${log.entityId ? html`<span class="mono small">${log.entityId}</span>` : ""}</dd>
                        <dt>IP</dt><dd class="mono">${log.ip || "—"}</dd>
                        <dt>Navegador</dt><dd class="small">${log.userAgent || "—"}</dd>
                    </dl>
                    <pre class="code">${JSON.stringify(log.metadata || {}, null, 2)}</pre>`
            });
        }
    });

    await load();
    return off;
}
