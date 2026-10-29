import { html, mount, $, onAction, formData, showFieldErrors, animateCounters } from "../core/dom.js";
import { api, request } from "../core/api.js";
import { session } from "../core/session.js";
import { queryParams, setQueryParams } from "../core/router.js";
import { ROLE, formatDate, formatDay } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { confirmDialog } from "../ui/modal.js";
import { avatar, roleBadge, pageLoader, relative } from "../ui/components.js";

const ROLE_ABOUT = {
    SUPER_ADMIN: "Control total: integraciones, administradores, usuarios, auditoría y todo el trabajo de análisis.",
    ADMIN: "Gestiona usuarios y analistas, revisa la auditoría y el estado del sistema.",
    ANALYST: "Revisa veredictos, gestiona casos de investigación, explora IOC y analiza tendencias.",
    USER: "Envía archivos para análisis y consulta los resultados de sus envíos."
};

function passwordLevel(value) {
    let level = 0;
    if (value.length >= 8) level++;
    if (/[a-z]/.test(value) && /[A-Z]/.test(value)) level++;
    if (/\d/.test(value)) level++;
    if (/[^A-Za-z0-9]/.test(value) || value.length >= 14) level++;
    return value ? Math.max(1, level) : 0;
}

export async function render(el) {
    mount(el, pageLoader());
    let profile = (await api.get("/profile")).profile;
    let tab = queryParams().tab === "security" ? "security" : "info";

    function syncSession() {
        session.set({ ...session.user, fullName: profile.fullName, avatarUrl: profile.avatarUrl, jobTitle: profile.jobTitle, department: profile.department });
    }

    function draw() {
        const p = profile;
        mount(el, html`
            <section class="card profile-hero reveal">
                <div class="profile-hero__cover"></div>
                <div class="profile-hero__body">
                    <div class="avatar-edit">
                        ${avatar(p, "xl")}
                        <label class="avatar-edit__btn tooltip" data-tip="Cambiar foto">
                            ${icon("camera", "icon--sm")}
                            <input type="file" accept="image/png,image/jpeg,image/gif,image/webp" data-slot="avatar-input" hidden>
                        </label>
                    </div>
                    <div class="profile-hero__info">
                        <div class="row row--wrap">${roleBadge(p.role)}${p.department ? html`<span class="badge badge--outline">${p.department}</span>` : ""}</div>
                        <div class="profile-hero__name" style="margin-top:8px">${p.fullName}</div>
                        <div class="muted">${p.jobTitle || ROLE[p.role]} · ${p.email}</div>
                    </div>
                    <div class="profile-stats">
                        <div><div class="profile-stats__value" data-count="${p.stats.analyses}">0</div><div class="profile-stats__label">Archivos enviados</div></div>
                        <div><div class="profile-stats__value text-danger" data-count="${p.stats.malicious}">0</div><div class="profile-stats__label">Maliciosos</div></div>
                        ${session.can("ANALYST") ? html`<div><div class="profile-stats__value text-primary" data-count="${p.stats.reviews}">0</div><div class="profile-stats__label">Revisiones</div></div>` : ""}
                    </div>
                </div>
            </section>

            <div class="grid grid--main-side" style="margin-top:20px">
                <section class="card reveal">
                    <div class="tabs">
                        <button class="tab ${tab === "info" ? "is-active" : ""}" data-action="tab" data-tab="info">${icon("user", "icon--sm")} Información personal</button>
                        <button class="tab ${tab === "security" ? "is-active" : ""}" data-action="tab" data-tab="security">${icon("lock", "icon--sm")} Seguridad</button>
                    </div>
                    <div class="card__body tab-panel" data-slot="panel"></div>
                </section>

                <aside class="stack">
                    <section class="card card--pad reveal">
                        <h4>Foto de perfil</h4>
                        <p class="muted small" style="margin:6px 0 16px">PNG, JPG, GIF o WEBP de máximo 2 MB. Se valida el contenido real de la imagen.</p>
                        <div class="row">
                            ${avatar(p, "lg")}
                            <div class="row row--wrap">
                                <label class="btn btn--sm">${icon("camera", "icon--sm")} Subir foto<input type="file" accept="image/png,image/jpeg,image/gif,image/webp" data-slot="avatar-input" hidden></label>
                                ${p.avatarUrl ? html`<button class="btn btn--sm btn--danger" data-action="remove-avatar">${icon("trash", "icon--sm")} Quitar</button>` : ""}
                            </div>
                        </div>
                    </section>
                    <section class="card card--pad reveal">
                        <h4>Tu rol: ${ROLE[p.role]}</h4>
                        <p class="muted small" style="margin-top:6px">${ROLE_ABOUT[p.role]}</p>
                        <div class="divider"></div>
                        <dl class="kv">
                            <dt>Miembro desde</dt><dd>${formatDay(p.createdAt)}</dd>
                            <dt>Último acceso</dt><dd>${p.lastLoginAt ? relative(p.lastLoginAt) : "—"}</dd>
                            <dt>Contraseña</dt><dd>${p.passwordChangedAt ? `Cambiada ${formatDate(p.passwordChangedAt)}` : "—"}</dd>
                        </dl>
                    </section>
                </aside>
            </div>
        `);

        animateCounters(el);
        el.querySelectorAll('[data-slot="avatar-input"]').forEach((input) => input.addEventListener("change", () => input.files[0] && uploadAvatar(input.files[0])));
        drawPanel();
    }

    function drawPanel() {
        const p = profile;
        const panel = $('[data-slot="panel"]', el);
        if (tab === "info") {
            mount(panel, html`
                <form class="form" data-slot="info-form">
                    <div class="form-grid">
                        <label class="field field--full"><span class="field__label">Nombre completo</span><input class="input" name="fullName" value="${p.fullName}" required minlength="3" maxlength="100"></label>
                        <label class="field"><span class="field__label">Cargo</span><input class="input" name="jobTitle" value="${p.jobTitle || ""}" maxlength="100" placeholder="Ej: Analista SOC"></label>
                        <label class="field"><span class="field__label">Área o departamento</span><input class="input" name="department" value="${p.department || ""}" maxlength="100" placeholder="Ej: Seguridad"></label>
                        <label class="field"><span class="field__label">Teléfono</span><input class="input" name="phone" value="${p.phone || ""}" maxlength="30" placeholder="+57 300 000 0000"></label>
                        <label class="field"><span class="field__label">Ubicación</span><input class="input" name="location" value="${p.location || ""}" maxlength="100" placeholder="Ciudad, país"></label>
                        <label class="field field--full"><span class="field__label">Sobre ti</span><textarea class="textarea" name="bio" maxlength="500" placeholder="Una breve descripción…">${p.bio || ""}</textarea><span class="field__hint">Máximo 500 caracteres</span></label>
                        <label class="field field--full"><span class="field__label">Correo electrónico</span><input class="input" value="${p.email}" disabled><span class="field__hint">El correo solo lo puede cambiar un administrador.</span></label>
                    </div>
                    <div class="row" style="justify-content:flex-end"><button class="btn btn--primary" type="submit">${icon("check")} Guardar cambios</button></div>
                </form>`);
            $('[data-slot="info-form"]', panel).addEventListener("submit", saveInfo);
        } else {
            mount(panel, html`
                <form class="form" data-slot="password-form" style="max-width:520px">
                    <div class="alert alert--info small">${icon("info")}<span>Al cambiar la contraseña se cerrarán tus sesiones en otros dispositivos.</span></div>
                    <label class="field"><span class="field__label">Contraseña actual</span><input class="input" type="password" name="currentPassword" autocomplete="current-password" required></label>
                    <label class="field"><span class="field__label">Nueva contraseña</span><input class="input" type="password" name="newPassword" autocomplete="new-password" required minlength="8">
                        <div class="password-meter" data-level="0"><span></span><span></span><span></span><span></span></div>
                        <span class="field__hint">Mínimo 8 caracteres con mayúsculas, minúsculas y números.</span>
                    </label>
                    <label class="field"><span class="field__label">Confirmar nueva contraseña</span><input class="input" type="password" name="confirmPassword" autocomplete="new-password" required></label>
                    <div><button class="btn btn--primary" type="submit">${icon("key")} Actualizar contraseña</button></div>
                </form>`);
            const form = $('[data-slot="password-form"]', panel);
            form.elements.newPassword.addEventListener("input", (event) => {
                $(".password-meter", form).dataset.level = passwordLevel(event.target.value);
            });
            form.addEventListener("submit", savePassword);
        }
    }

    async function saveInfo(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector('[type="submit"]');
        button.classList.add("is-loading");
        try {
            const result = await api.patch("/profile", formData(form));
            profile = result.profile;
            syncSession();
            toast.success("Tus datos se guardaron", "Perfil actualizado");
            draw();
        } catch (error) {
            showFieldErrors(form, error.fields);
            toast.error(error.message);
        } finally {
            button.classList.remove("is-loading");
        }
    }

    async function savePassword(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector('[type="submit"]');
        button.classList.add("is-loading");
        try {
            await api.put("/profile/password", formData(form));
            form.reset();
            $(".password-meter", form).dataset.level = 0;
            showFieldErrors(form, {});
            toast.success("Usa la nueva contraseña la próxima vez que inicies sesión", "Contraseña actualizada");
        } catch (error) {
            showFieldErrors(form, error.fields);
            toast.error(error.message);
        } finally {
            button.classList.remove("is-loading");
        }
    }

    async function uploadAvatar(file) {
        if (file.size > 2 * 1024 * 1024) {
            toast.error("La imagen supera los 2 MB");
            return;
        }
        const body = new FormData();
        body.append("avatar", file);
        try {
            const result = await request("PUT", "/profile/avatar", { body });
            profile = result.profile;
            syncSession();
            toast.success("Tu nueva foto ya aparece en el menú", "Foto actualizada");
            draw();
        } catch (error) {
            toast.error(error.message);
        }
    }

    const off = onAction(el, {
        tab: (button) => {
            tab = button.dataset.tab;
            setQueryParams({ tab: tab === "security" ? "security" : "" });
            el.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t === button));
            drawPanel();
        },
        "remove-avatar": async () => {
            if (!(await confirmDialog({ title: "Quitar foto de perfil", message: "Se mostrarán tus iniciales en su lugar.", confirmText: "Quitar foto", danger: true }))) return;
            profile = (await api.delete("/profile/avatar")).profile;
            syncSession();
            toast.success("Foto eliminada");
            draw();
        }
    });

    draw();
    return off;
}
