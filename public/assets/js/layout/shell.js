/**
 * Estructura principal: barra lateral (con la tarjeta del usuario arriba a la izquierda),
 * menú según el rol y barra superior.
 */
import { html, mount, $, $$, onAction } from "../core/dom.js";
import { session } from "../core/session.js";
import { currentPath, navigate } from "../core/router.js";
import { toggleTheme, currentTheme } from "../core/theme.js";
import { ROLE } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { avatar } from "../ui/components.js";

export const NAV = [
    {
        section: "General",
        items: [
            { path: "/", label: "Panel", icon: "dashboard" },
            { path: "/analyze", label: "Analizar archivo", icon: "upload" },
            { path: "/analyses", label: "Análisis", icon: "list", labelFor: { USER: "Mis análisis" } }
        ]
    },
    {
        section: "Centro de análisis",
        minRole: "ANALYST",
        items: [
            { path: "/review", label: "Cola de revisión", icon: "check-square", badge: "pendingReview" },
            { path: "/analytics", label: "Analítica", icon: "bar-chart" },
            { path: "/cases", label: "Casos", icon: "briefcase", badge: "myCases" },
            { path: "/iocs", label: "Indicadores (IOC)", icon: "radar" }
        ]
    },
    {
        section: "Administración",
        minRole: "ADMIN",
        items: [
            { path: "/users", label: "Usuarios", icon: "users" },
            { path: "/audit", label: "Auditoría", icon: "scroll" },
            { path: "/system", label: "Sistema", icon: "server" }
        ]
    },
    {
        section: "Cuenta",
        items: [{ path: "/profile", label: "Mi perfil", icon: "user" }]
    }
];

const badges = {};

function isActive(path) {
    const current = currentPath();
    return path === "/" ? current === "/" : current === path || current.startsWith(`${path}/`);
}

function userCard(user) {
    // Nombre y rol a la izquierda, foto al lado
    return html`
        <button class="user-card" data-action="user-menu" aria-haspopup="menu">
            ${avatar(user)}
            <span class="user-card__info">
                <span class="user-card__name" title="${user.fullName}">${user.fullName}</span>
                <span class="user-card__role">${ROLE[user.role]}</span>
            </span>
            <span class="user-card__chevron">${icon("chevrons-up-down", "icon--sm")}</span>
        </button>`;
}

function navTemplate(user) {
    return NAV.filter((group) => !group.minRole || session.can(group.minRole)).map((group) => html`
        <div class="nav__section">${group.section}</div>
        ${group.items.map((item) => html`
            <a class="nav__link ${isActive(item.path) ? "is-active" : ""}" href="#${item.path}" data-path="${item.path}">
                ${icon(item.icon)}
                <span>${item.labelFor?.[user.role] || item.label}</span>
                ${item.badge && badges[item.badge] ? html`<span class="nav__badge">${badges[item.badge]}</span>` : ""}
            </a>`)}
    `);
}

export function renderShell(root) {
    const user = session.user;
    mount(root, html`
        <div class="app">
            <aside class="sidebar" aria-label="Navegación principal">
                <a class="brand" href="#/">
                    <span class="brand__logo">${icon("shield-check")}</span>
                    <span><span class="brand__name">SACM</span><span class="brand__tag">Análisis y Control de Malware</span></span>
                </a>
                <div data-slot="user">${userCard(user)}</div>
                <nav class="nav" data-slot="nav">${navTemplate(user)}</nav>
                <div class="sidebar__footer">
                    <button class="nav__link" data-action="theme">${icon(currentTheme() === "dark" ? "sun" : "moon")}<span>Modo ${currentTheme() === "dark" ? "claro" : "oscuro"}</span></button>
                    <button class="nav__link" data-action="logout">${icon("log-out")}<span>Cerrar sesión</span></button>
                </div>
            </aside>
            <div class="backdrop" data-action="close-nav"></div>
            <div class="main">
                <header class="topbar">
                    <button class="btn btn--ghost btn--icon menu-toggle" data-action="open-nav" aria-label="Abrir menú">${icon("menu")}</button>
                    <div class="topbar__title">
                        <div class="topbar__crumbs" data-slot="crumbs">SACM</div>
                        <h1 data-slot="title">Panel</h1>
                    </div>
                    <div class="topbar__actions">
                        <button class="btn btn--ghost btn--icon tooltip" data-action="theme" data-tip="Cambiar tema" aria-label="Cambiar tema">${icon(currentTheme() === "dark" ? "sun" : "moon")}</button>
                        <a class="btn btn--primary" href="#/analyze">${icon("upload")}<span class="btn__label">Analizar archivo</span></a>
                    </div>
                </header>
                <main class="content" id="content" tabindex="-1"></main>
            </div>
        </div>
    `);

    const app = $(".app", root);

    onAction(root, {
        theme: () => {
            toggleTheme();
            refreshShell();
        },
        logout: () => session.logout(),
        "open-nav": () => app.classList.add("nav-open"),
        "close-nav": () => app.classList.remove("nav-open"),
        "user-menu": (button) => openUserMenu(button)
    });

    root.addEventListener("click", (event) => {
        if (event.target.closest(".nav__link[href]")) app.classList.remove("nav-open");
    });

    session.onChange(() => refreshShell());
    return $("#content", root);
}

function openUserMenu(button) {
    document.querySelector(".dropdown")?.remove();
    const rect = button.getBoundingClientRect();
    const menu = document.createElement("div");
    menu.className = "dropdown";
    menu.setAttribute("role", "menu");
    menu.style.left = `${rect.left}px`;
    menu.style.top = `${rect.bottom + 8}px`;
    menu.style.width = `${rect.width}px`;
    mount(menu, html`
        <div class="person" style="padding:8px 12px 10px">
            <div style="min-width:0"><div class="strong truncate">${session.user.fullName}</div><div class="subtle small truncate">${session.user.email}</div></div>
        </div>
        <div class="dropdown__sep"></div>
        <button class="dropdown__item" data-go="/profile">${icon("user")} Mi perfil</button>
        <button class="dropdown__item" data-go="/profile?tab=security">${icon("lock")} Seguridad y contraseña</button>
        <button class="dropdown__item" data-go="/analyses">${icon("list")} Mis análisis</button>
        <div class="dropdown__sep"></div>
        <button class="dropdown__item dropdown__item--danger" data-logout>${icon("log-out")} Cerrar sesión</button>
    `);
    document.body.append(menu);

    const close = (event) => {
        if (event && menu.contains(event.target) && !event.target.closest("button")) return;
        menu.remove();
        document.removeEventListener("mousedown", close);
    };
    menu.addEventListener("click", (event) => {
        const go = event.target.closest("[data-go]");
        if (go) navigate(go.dataset.go);
        if (event.target.closest("[data-logout]")) session.logout();
        close();
    });
    setTimeout(() => document.addEventListener("mousedown", close), 0);
}

/** Vuelve a pintar la tarjeta del usuario y el menú (tras editar el perfil, cambiar tema, etc.) */
export function refreshShell() {
    const userSlot = document.querySelector('[data-slot="user"]');
    const navSlot = document.querySelector('[data-slot="nav"]');
    if (userSlot && session.user) mount(userSlot, userCard(session.user));
    if (navSlot && session.user) mount(navSlot, navTemplate(session.user));
    $$('[data-action="theme"]').forEach((btn) => {
        const isButtonInSidebar = btn.classList.contains("nav__link");
        mount(btn, isButtonInSidebar
            ? html`${icon(currentTheme() === "dark" ? "sun" : "moon")}<span>Modo ${currentTheme() === "dark" ? "claro" : "oscuro"}</span>`
            : icon(currentTheme() === "dark" ? "sun" : "moon"));
    });
}

export function setBadges(values) {
    Object.assign(badges, values);
    refreshShell();
}

export function setTitle(title, crumbs = "SACM") {
    const titleSlot = document.querySelector('[data-slot="title"]');
    const crumbSlot = document.querySelector('[data-slot="crumbs"]');
    if (titleSlot) titleSlot.textContent = title;
    if (crumbSlot) crumbSlot.textContent = crumbs;
    document.title = `${title} · SACM`;
    $$(".nav__link[data-path]").forEach((link) => link.classList.toggle("is-active", isActive(link.dataset.path)));
}
