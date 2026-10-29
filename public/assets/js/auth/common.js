/** Utilidades compartidas por las páginas públicas (inicio, login y registro) */
import { mount, html } from "../core/dom.js";
import { icon } from "../ui/icons.js";
import { toggleTheme, currentTheme } from "../core/theme.js";

/** Reemplaza cada <span data-icon="nombre"> por su SVG */
export function hydrateIcons(root = document) {
    root.querySelectorAll("[data-icon]").forEach((el) => {
        const extra = el.classList.contains("radar__core") ? "icon--xl" : "";
        if (el.closest(".input-group") && !el.closest("button")) {
            el.outerHTML = icon(el.dataset.icon).value;
        } else {
            mount(el, icon(el.dataset.icon, extra));
        }
    });
}

export function setupThemeToggle() {
    const button = document.querySelector("[data-theme-toggle]");
    if (!button) return;
    const paint = () => mount(button, icon(currentTheme() === "dark" ? "sun" : "moon"));
    paint();
    button.addEventListener("click", () => {
        toggleTheme();
        paint();
    });
}

export function setupPasswordToggle(root = document) {
    root.querySelectorAll("[data-toggle-password]").forEach((button) => {
        const input = button.parentElement.querySelector("input");
        const paint = () => mount(button, icon(input.type === "password" ? "eye" : "eye-off", "icon--sm"));
        paint();
        button.addEventListener("click", () => {
            input.type = input.type === "password" ? "text" : "password";
            paint();
        });
    });
}

export function showAlert(slot, message, type = "danger") {
    mount(slot, html`<div class="alert alert--${type}" style="margin-top:20px">${icon(type === "danger" ? "alert-triangle" : "info")}<span>${message}</span></div>`);
}
