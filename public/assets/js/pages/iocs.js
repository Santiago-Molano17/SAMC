import { html, mount, $, onAction, debounce, copyText } from "../core/dom.js";
import { api } from "../core/api.js";
import { IOC_TYPE, formatNumber } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { openModal } from "../ui/modal.js";
import { emptyState, skeletonRows, pagination, relative, verdictBadge, riskBar } from "../ui/components.js";

export async function render(el) {
    const state = { q: "", type: "", malicious: false, page: 1 };

    mount(el, html`
        <div class="page-header reveal">
            <div>
                <h2>Indicadores de compromiso</h2>
                <p class="page-header__subtitle">URLs, dominios, IP, rutas y claves de registro extraídos de todas las muestras. Úsalos para buscar relaciones entre ataques.</p>
            </div>
        </div>
        <section class="card reveal">
            <div class="toolbar">
                <div class="input-group search" style="flex:1">${icon("search")}<input class="input" type="search" name="q" placeholder="Buscar un dominio, IP, URL o ruta…"></div>
                <select class="select" name="type"><option value="">Todos los tipos</option>${Object.entries(IOC_TYPE).map(([k, v]) => html`<option value="${k}">${v}</option>`)}</select>
                <button class="btn" data-action="malicious">${icon("alert-octagon")} Solo maliciosos</button>
            </div>
            <div data-slot="types" class="toolbar" style="padding-top:10px;padding-bottom:10px"></div>
            <div data-slot="results"></div>
        </section>
    `);

    const results = $('[data-slot="results"]', el);

    async function load() {
        mount(results, html`<div class="table-wrap"><table class="table"><tbody>${skeletonRows(8, 5)}</tbody></table></div>`);
        const data = await api.get("/analytics/iocs", { q: state.q, type: state.type, malicious: state.malicious ? "true" : undefined, page: state.page, pageSize: 20 });

        mount($('[data-slot="types"]', el), html`${data.types.map((t) => html`
            <button class="chip" data-action="type" data-type="${t.type}" style="cursor:pointer">${IOC_TYPE[t.type]} <strong>${formatNumber(t.total)}</strong></button>`)}`);

        if (!data.items.length) {
            mount(results, emptyState({ iconName: "radar", title: "No hay indicadores con esos filtros" }));
            return;
        }

        mount(results, html`
            <div class="table-wrap"><table class="table">
                <thead><tr><th>Tipo</th><th>Indicador</th><th class="num">Muestras</th><th>Reputación</th><th>Visto por última vez</th><th></th></tr></thead>
                <tbody class="reveal-stagger">${data.items.map((i) => html`<tr>
                    <td><span class="badge badge--outline">${IOC_TYPE[i.type]}</span></td>
                    <td class="mono break" style="max-width:480px">${i.value}</td>
                    <td class="num strong">${i.analyses}</td>
                    <td>${i.malicious
                        ? html`<span class="badge badge--malicious">Malicioso</span>`
                        : i.seenInMalicious ? html`<span class="badge badge--suspicious">En muestras maliciosas</span>` : html`<span class="subtle small">Sin reportes</span>`}</td>
                    <td class="muted nowrap">${relative(i.lastSeen)}</td>
                    <td class="nowrap">
                        <button class="btn btn--ghost btn--icon btn--sm" data-action="copy" data-value="${i.value}" aria-label="Copiar">${icon("copy", "icon--sm")}</button>
                        <button class="btn btn--sm" data-action="pivot" data-type="${i.type}" data-value="${i.value}">${icon("git-merge", "icon--sm")} Muestras</button>
                    </td>
                </tr>`)}</tbody>
            </table></div>
            ${pagination(data)}
        `);
    }

    async function pivot(type, value) {
        const { items } = await api.get("/analytics/iocs/analyses", { type, value });
        openModal({
            title: "Muestras relacionadas",
            subtitle: value,
            size: "lg",
            content: html`<div class="stack" style="gap:8px">${items.map((a) => html`
                <a class="card row row--between" style="padding:12px 14px;color:inherit" href="#/analyses/${a.id}" data-close>
                    <span class="truncate strong">${a.originalName}</span>
                    <span class="row">${verdictBadge(a.finalVerdict)}${riskBar(a.riskScore)}<span class="subtle small nowrap">${relative(a.submittedAt)}</span></span>
                </a>`)}</div>`
        });
    }

    $('[name="q"]', el).addEventListener("input", debounce((event) => {
        state.q = event.target.value.trim();
        state.page = 1;
        load();
    }, 350));
    $('[name="type"]', el).addEventListener("change", (event) => {
        state.type = event.target.value;
        state.page = 1;
        load();
    });

    const off = onAction(el, {
        malicious: (button) => {
            state.malicious = !state.malicious;
            button.classList.toggle("btn--danger", state.malicious);
            state.page = 1;
            load();
        },
        type: (button) => {
            state.type = button.dataset.type;
            $('[name="type"]', el).value = state.type;
            state.page = 1;
            load();
        },
        page: (button) => {
            state.page = Number(button.dataset.page);
            load();
        },
        copy: async (button) => {
            if (await copyText(button.dataset.value)) toast.success("Copiado al portapapeles");
        },
        pivot: (button) => pivot(button.dataset.type, button.dataset.value).catch((e) => toast.error(e.message))
    });

    await load();
    return off;
}
