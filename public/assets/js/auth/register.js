import { formData, showFieldErrors, $ } from "../core/dom.js";
import { api } from "../core/api.js";
import { hydrateIcons, setupThemeToggle, showAlert } from "./common.js";

hydrateIcons();
setupThemeToggle();

const form = $("#register-form");
const alertSlot = $('[data-slot="alert"]');

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector('[type="submit"]');
    const data = formData(form);

    if (data.password !== data.confirmPassword) {
        showFieldErrors(form, { confirmPassword: "Las contraseñas no coinciden" });
        return;
    }

    button.classList.add("is-loading");
    alertSlot.replaceChildren();
    try {
        await api.post("/auth/register", data);
        location.replace("/login?registered=1");
    } catch (error) {
        showFieldErrors(form, error.fields);
        showAlert(alertSlot, error.message);
        button.classList.remove("is-loading");
    }
});
