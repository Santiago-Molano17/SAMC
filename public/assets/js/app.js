/**
 * Punto de entrada de la aplicación (app.html).
 */
import { html, mount } from "./core/dom.js";
import { setUnauthorizedHandler } from "./core/api.js";
import { session } from "./core/session.js";
import { route, setNotFound, startRouter } from "./core/router.js";
import { initTheme } from "./core/theme.js";
import { renderShell, setTitle } from "./layout/shell.js";
import { destroyCharts } from "./ui/charts.js";
import { emptyState } from "./ui/components.js";
import { icon } from "./ui/icons.js";

import * as dashboard from "./pages/dashboard.js";
import * as analyze from "./pages/analyze.js";
import * as analyses from "./pages/analyses.js";
import * as analysisDetail from "./pages/analysis-detail.js";
import * as analytics from "./pages/analytics.js";
import * as iocs from "./pages/iocs.js";
import * as cases from "./pages/cases.js";
import * as caseDetail from "./pages/case-detail.js";
import * as profile from "./pages/profile.js";
import * as users from "./pages/users.js";
import * as audit from "./pages/audit.js";
import * as system from "./pages/system.js";

initTheme();

route("/", { title: "Panel", crumbs: "Inicio", render: dashboard.render });
route("/analyze", { title: "Analizar archivo", crumbs: "Análisis", render: analyze.render });
route("/analyses", { title: "Análisis", crumbs: "Análisis", render: analyses.render });
route("/analyses/:id", { title: "Reporte de análisis", crumbs: "Análisis", render: analysisDetail.render });
route("/review", { title: "Cola de revisión", crumbs: "Centro de análisis", minRole: "ANALYST", render: analyses.renderReview });
route("/analytics", { title: "Analítica", crumbs: "Centro de análisis", minRole: "ANALYST", render: analytics.render });
route("/iocs", { title: "Indicadores de compromiso", crumbs: "Centro de análisis", minRole: "ANALYST", render: iocs.render });
route("/cases", { title: "Casos", crumbs: "Centro de análisis", minRole: "ANALYST", render: cases.render });
route("/cases/:id", { title: "Caso", crumbs: "Casos", minRole: "ANALYST", render: caseDetail.render });
route("/profile", { title: "Mi perfil", crumbs: "Cuenta", render: profile.render });
route("/users", { title: "Usuarios", crumbs: "Administración", minRole: "ADMIN", render: users.render });
route("/audit", { title: "Auditoría", crumbs: "Administración", minRole: "ADMIN", render: audit.render });
route("/system", { title: "Sistema", crumbs: "Administración", minRole: "ADMIN", render: system.render });

setNotFound({
    title: "No encontrado",
    render: (el, params, forbidden) => mount(el, html`<div class="card">${emptyState({
        iconName: forbidden ? "lock" : "search",
        title: forbidden ? "No tienes acceso a esta sección" : "Esta página no existe",
        message: forbidden ? "Tu rol no tiene permisos para verla." : "Revisa la dirección o vuelve al panel.",
        action: html`<a class="btn btn--primary" href="#/">${icon("dashboard", "icon--sm")} Ir al panel</a>`
    })}</div>`)
});

async function boot() {
    const user = await session.load();
    if (!user) {
        location.replace("/login");
        return;
    }

    setUnauthorizedHandler(() => location.replace("/login?expired=1"));
    const content = renderShell(document.getElementById("app"));

    startRouter(async ({ route: current, params }) => {
        destroyCharts();
        document.querySelector(".dropdown")?.remove();
        setTitle(current.title, current.crumbs);
        content.classList.remove("page-enter");
        void content.offsetWidth;
        content.classList.add("page-enter");
        window.scrollTo({ top: 0 });

        try {
            return await current.render(content, params, current.forbidden);
        } catch (error) {
            console.error(error);
            mount(content, html`<div class="card">${emptyState({
                iconName: "alert-triangle",
                title: error.status === 404 ? "No encontramos lo que buscas" : "No se pudo cargar esta sección",
                message: error.message,
                action: html`<a class="btn" href="#/">Volver al panel</a>`
            })}</div>`);
            return null;
        }
    });
}

boot();
