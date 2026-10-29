import { formData, showFieldErrors, $ } from "../core/dom.js";
import { api } from "../core/api.js";
import { hydrateIcons, setupThemeToggle, setupPasswordToggle, showAlert } from "./common.js";

hydrateIcons();
setupThemeToggle();
setupPasswordToggle();

const form = $("#login-form");
const alertSlot = $('[data-slot="alert"]');
const params = new URLSearchParams(location.search);

if (params.has("expired")) showAlert(alertSlot, "Tu sesión expiró. Inicia sesión de nuevo.", "info");
if (params.has("registered")) showAlert(alertSlot, "Cuenta creada. Ya puedes iniciar sesión.", "info");

// Si ya hay sesión, se va directo al panel
api.get("/auth/me").then(() => location.replace("/app")).catch(() => {});

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector('[type="submit"]');
    const data = formData(form);

    const fields = {};
    if (!data.email) fields.email = "Ingresa tu correo";
    if (!data.password) fields.password = "Ingresa tu contraseña";
    showFieldErrors(form, fields);
    if (Object.keys(fields).length) return;

    button.classList.add("is-loading");
    alertSlot.replaceChildren();
    try {
        await api.post("/auth/login", data);
        location.replace("/app");
    } catch (error) {
        showFieldErrors(form, error.fields);
        showAlert(alertSlot, error.message);
        button.classList.remove("is-loading");
    }
});
