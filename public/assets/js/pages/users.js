import { html, mount, $, onAction, debounce, formData, showFieldErrors, raw } from "../core/dom.js";
import { api } from "../core/api.js";
import { session } from "../core/session.js";
import { ROLE, formatNumber } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { openModal, confirmDialog } from "../ui/modal.js";
import { avatar, roleBadge, emptyState, skeletonRows, pagination, relative, kpiCard } from "../ui/components.js";
import { animateCounters } from "../core/dom.js";

const LEVEL = { USER: 1, ANALYST: 2, ADMIN: 3, SUPER_ADMIN: 4 };

/** Roles que el usuario actual puede asignar */
function assignableRoles() {
    return session.user.role === "SUPER_ADMIN" ? Object.keys(ROLE) : ["ANALYST", "USER"];
}

const canManage = (target) => target.id !== session.user.id &&
    (session.user.role === "SUPER_ADMIN" || LEVEL[target.role] < LEVEL.ADMIN);

function userForm() {
    return html`<form class="form" data-slot="user-form">
        <div class="form-grid">
            <label class="field field--full"><span class="field__label">Nombre completo</span><input class="input" name="fullName" required minlength="3"></label>
            <label class="field field--full"><span class="field__label">Correo</span><input class="input" type="email" name="email" required></label>
            <label class="field"><span class="field__label">Contraseña temporal</span><input class="input" type="text" name="password" required minlength="8" autocomplete="off"><span class="field__hint">Mayúscula, minúscula y número</span></label>
            <label class="field"><span class="field__label">Rol</span>
                <select class="select" name="role">${assignableRoles().map((r) => html`<option value="${r}" ${r === "USER" ? raw("selected") : ""}>${ROLE[r]}</option>`)}</select>
            </label>
            <label class="field"><span class="field__label">Cargo</span><input class="input" name="jobTitle"></label>
            <label class="field"><span class="field__label">Departamento</span><input class="input" name="department"></label>
        </div>
    </form>`;
}

export async function render(el) {
    const state = { q: "", role: "", status: "", page: 1 };

    mount(el, html`
        <div class="page-header reveal">
            <div>
                <h2>Usuarios y roles</h2>
                <p class="page-header__subtitle">${session.user.role === "SUPER_ADMIN"
                    ? "Como super administrador puedes gestionar a todos, incluidos otros administradores."
                    : "Puedes gestionar usuarios y analistas. Los administradores los gestiona el super administrador."}</p>
            </div>
            <div class="page-header__actions"><button class="btn btn--primary" data-action="create">${icon("user-plus")} Nuevo usuario</button></div>
        </div>
        <div class="grid grid--kpi reveal-stagger" data-slot="summary" style="margin-bottom:20px"></div>
        <section class="card reveal">
            <div class="toolbar">
                <div class="input-group search" style="flex:1">${icon("search")}<input class="input" type="search" name="q" placeholder="Buscar por nombre o correo…"></div>
                <select class="select" name="role"><option value="">Todos los roles</option>${Object.entries(ROLE).map(([k, v]) => html`<option value="${k}">${v}</option>`)}</select>
                <select class="select" name="status"><option value="">Todos los estados</option><option value="active">Activos</option><option value="suspended">Suspendidos</option></select>
            </div>
            <div data-slot="results"></div>
        </section>
    `);

    const results = $('[data-slot="results"]', el);
    let lastItems = [];

    async function load() {
        mount(results, html`<div class="table-wrap"><table class="table"><tbody>${skeletonRows(6, 6)}</tbody></table></div>`);
        const data = await api.get("/admin/users", { ...state, pageSize: 15 });
        lastItems = data.items;

        mount($('[data-slot="summary"]', el), html`
            ${kpiCard({ label: "Usuarios", value: data.summary.total, iconName: "users" })}
            ${kpiCard({ label: "Activos", value: data.summary.active, iconName: "check-circle", tone: "success" })}
            ${kpiCard({ label: "Analistas", value: data.summary.analysts, iconName: "target", tone: "accent" })}
            ${kpiCard({ label: "Suspendidos", value: data.summary.suspended, iconName: "ban", tone: "danger" })}`);
        animateCounters($('[data-slot="summary"]', el));

        if (!data.items.length) {
            mount(results, emptyState({ iconName: "users", title: "No hay usuarios con esos filtros" }));
            return;
        }

        mount(results, html`
            <div class="table-wrap"><table class="table">
                <thead><tr><th>Usuario</th><th>Rol</th><th>Estado</th><th class="num">Análisis</th><th>Último acceso</th><th></th></tr></thead>
                <tbody class="reveal-stagger">${data.items.map((u) => html`<tr>
                    <td><div class="person">${avatar(u, "sm")}<div style="min-width:0"><div class="strong truncate">${u.fullName} ${u.id === session.user.id ? html`<span class="badge badge--primary">Tú</span>` : ""}</div><div class="subtle small truncate">${u.email}${u.jobTitle ? ` · ${u.jobTitle}` : ""}</div></div></div></td>
                    <td>${canManage(u) ? html`
                        <select class="select" style="height:32px;width:auto;min-width:170px" data-role-for="${u.id}" aria-label="Rol">
                            ${assignableRoles().map((r) => html`<option value="${r}" ${u.role === r ? raw("selected") : ""}>${ROLE[r]}</option>`)}
                        </select>` : roleBadge(u.role)}</td>
                    <td>${u.locked ? html`<span class="badge badge--warning">${icon("lock", "icon--sm")} Bloqueado</span>` : u.status === "active" ? html`<span class="badge badge--success badge--dot">Activo</span>` : html`<span class="badge badge--danger badge--dot">Suspendido</span>`}</td>
                    <td class="num">${formatNumber(u.analysesCount)}</td>
                    <td class="muted nowrap">${u.lastLoginAt ? relative(u.lastLoginAt) : "Nunca"}</td>
                    <td class="nowrap">${canManage(u) ? html`
                        ${u.locked ? html`<button class="btn btn--sm" data-action="unlock" data-id="${u.id}">${icon("unlock", "icon--sm")} Desbloquear</button>` : ""}
                        <button class="btn btn--sm" data-action="toggle" data-id="${u.id}">${u.status === "active" ? html`${icon("ban", "icon--sm")} Suspender` : html`${icon("check", "icon--sm")} Activar`}</button>
                        <button class="btn btn--ghost btn--icon btn--sm tooltip" data-tip="Eliminar" data-action="delete" data-id="${u.id}" aria-label="Eliminar">${icon("trash", "icon--sm")}</button>` : ""}
                    </td>
                </tr>`)}</tbody>
            </table></div>
            ${pagination(data)}
        `);

        results.querySelectorAll("[data-role-for]").forEach((select) => select.addEventListener("change", () => patch(select.dataset.roleFor, { role: select.value }, `Rol cambiado a ${ROLE[select.value]}`)));
    }

    async function patch(id, changes, message) {
        try {
            await api.patch(`/admin/users/${id}`, changes);
            toast.success(message);
        } catch (error) {
            toast.error(error.message);
        }
        load();
    }

    const find = (id) => lastItems.find((u) => u.id === id);

    $('[name="q"]', el).addEventListener("input", debounce((event) => {
        state.q = event.target.value.trim();
        state.page = 1;
        load();
    }, 350));
    el.querySelectorAll(".toolbar select").forEach((select) => select.addEventListener("change", () => {
        state[select.name] = select.value;
        state.page = 1;
        load();
    }));

    const off = onAction(el, {
        create: () => openModal({
            title: "Nuevo usuario",
            subtitle: "Comparte la contraseña temporal por un canal seguro; el usuario puede cambiarla en su perfil.",
            content: userForm(),
            footer: html`<button class="btn" data-close>Cancelar</button><button class="btn btn--primary" data-submit>${icon("user-plus", "icon--sm")} Crear usuario</button>`,
            onOpen: (modal, close) => {
                const form = $('[data-slot="user-form"]', modal);
                const submit = async (event) => {
                    event?.preventDefault();
                    try {
                        const result = await api.post("/admin/users", formData(form));
                        toast.success(`${result.user.fullName} ya puede iniciar sesión`, "Usuario creado");
                        close(true);
                        load();
                    } catch (error) {
                        showFieldErrors(form, error.fields);
                        toast.error(error.message);
                    }
                };
                form.addEventListener("submit", submit);
                $("[data-submit]", modal).addEventListener("click", submit);
            }
        }),
        toggle: (button) => {
            const user = find(button.dataset.id);
            const next = user.status === "active" ? "suspended" : "active";
            patch(user.id, { status: next }, next === "active" ? `${user.fullName} fue reactivado` : `${user.fullName} fue suspendido`);
        },
        unlock: (button) => patch(button.dataset.id, { unlock: true }, "Cuenta desbloqueada"),
        delete: async (button) => {
            const user = find(button.dataset.id);
            const ok = await confirmDialog({
                title: "Eliminar usuario",
                message: `Se eliminará la cuenta de ${user.fullName}. Sus análisis y notas se conservan sin autor. Esta acción no se puede deshacer.`,
                confirmText: "Eliminar",
                danger: true
            });
            if (!ok) return;
            try {
                await api.delete(`/admin/users/${user.id}`);
                toast.success("Usuario eliminado");
                load();
            } catch (error) {
                toast.error(error.message);
            }
        },
        page: (button) => {
            state.page = Number(button.dataset.page);
            load();
        }
    });

    await load();
    return off;
}
