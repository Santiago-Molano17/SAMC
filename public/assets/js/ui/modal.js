import { html, mount, $ } from "../core/dom.js";
import { icon } from "./icons.js";

/**
 * Abre un modal. `render(body, close)` recibe el contenedor del cuerpo.
 * Devuelve una promesa que se resuelve con el valor pasado a close().
 */
export function openModal({ title, subtitle, size = "", content, footer, onOpen }) {
    return new Promise((resolve) => {
        const backdrop = document.createElement("div");
        backdrop.className = "modal-backdrop";
        mount(backdrop, html`
            <div class="modal ${size ? `modal--${size}` : ""}" role="dialog" aria-modal="true" aria-label="${title}">
                <div class="modal__header">
                    <div>
                        <h2>${title}</h2>
                        ${subtitle ? html`<p class="muted small">${subtitle}</p>` : ""}
                    </div>
                    <button class="btn btn--ghost btn--icon btn--sm" data-close aria-label="Cerrar">${icon("x")}</button>
                </div>
                <div class="modal__body">${content}</div>
                ${footer ? html`<div class="modal__footer">${footer}</div>` : ""}
            </div>
        `);

        const previousFocus = document.activeElement;
        const close = (value) => {
            backdrop.classList.add("is-leaving");
            backdrop.addEventListener("animationend", () => backdrop.remove(), { once: true });
            document.removeEventListener("keydown", onKey);
            previousFocus?.focus?.();
            resolve(value);
        };
        const onKey = (event) => {
            if (event.key === "Escape") close(null);
        };

        backdrop.addEventListener("mousedown", (event) => {
            if (event.target === backdrop) close(null);
        });
        backdrop.querySelectorAll("[data-close]").forEach((el) => el.addEventListener("click", () => close(null)));
        document.addEventListener("keydown", onKey);
        document.body.append(backdrop);

        const modal = $(".modal", backdrop);
        onOpen?.(modal, close);
        ($("input, textarea, select", modal) || $("[data-confirm]", modal))?.focus();
    });
}

export function confirmDialog({ title, message, confirmText = "Confirmar", danger = false }) {
    return openModal({
        title,
        content: html`<p class="muted">${message}</p>`,
        footer: html`
            <button class="btn" data-close>Cancelar</button>
            <button class="btn ${danger ? "btn--danger" : "btn--primary"}" data-confirm>${confirmText}</button>
        `,
        onOpen: (modal, close) => {
            $("[data-confirm]", modal).addEventListener("click", () => close(true));
        }
    }).then(Boolean);
}
