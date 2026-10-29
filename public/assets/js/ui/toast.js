import { html, mount } from "../core/dom.js";
import { icon } from "./icons.js";

const ICONS = { success: "check", error: "alert-triangle", info: "info" };

function container() {
    let root = document.querySelector(".toasts");
    if (!root) {
        root = document.createElement("div");
        root.className = "toasts";
        root.setAttribute("role", "status");
        root.setAttribute("aria-live", "polite");
        document.body.append(root);
    }
    return root;
}

export function toast(message, { type = "success", title, duration = 4200 } = {}) {
    const element = document.createElement("div");
    element.className = `toast toast--${type}`;
    mount(element, html`
        <div class="toast__icon">${icon(ICONS[type], "icon--sm")}</div>
        <div>
            ${title ? html`<div class="toast__title">${title}</div>` : ""}
            <div class="toast__message">${message}</div>
        </div>
    `);
    container().append(element);

    const close = () => {
        element.classList.add("is-leaving");
        element.addEventListener("animationend", () => element.remove(), { once: true });
    };
    element.addEventListener("click", close);
    setTimeout(close, duration);
}

toast.success = (message, title) => toast(message, { type: "success", title });
toast.error = (message, title = "Algo salió mal") => toast(message, { type: "error", title, duration: 6000 });
toast.info = (message, title) => toast(message, { type: "info", title });
