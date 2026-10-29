import { html, mount, $, onAction } from "../core/dom.js";
import { api, upload } from "../core/api.js";
import { formatBytes } from "../core/format.js";
import { icon } from "../ui/icons.js";
import { toast } from "../ui/toast.js";
import { verdictBadge, gauge, animateGauges } from "../ui/components.js";
import { animateCounters } from "../core/dom.js";

const STEPS = [
    { id: "upload", label: "Subiendo el archivo de forma segura" },
    { id: "static", label: "Identificando el tipo real y calculando hashes" },
    { id: "rules", label: "Aplicando reglas de comportamiento (MITRE ATT&CK)" },
    { id: "intel", label: "Consultando servicios de inteligencia de amenazas" },
    { id: "score", label: "Calculando el puntaje de riesgo" }
];

const ENGINE_ICONS = { sacm_static: "fingerprint", sacm_rules: "target", virustotal: "shield", malwarebazaar: "bug", circl_hashlookup: "database", urlhaus: "globe" };

// Archivo de prueba estándar de la industria (inofensivo): https://www.eicar.org
const EICAR_TEST = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].join("");

export async function render(el) {
    const { items: engines, maxUploadMb } = await api.get("/analyses/engines");
    let selected = null;
    let polling = null;
    let ticker = null;

    mount(el, html`
        <div class="page-header reveal">
            <div>
                <h2>Analizar un archivo</h2>
                <p class="page-header__subtitle">El archivo nunca se ejecuta: se inspecciona su estructura y se consulta su reputación.</p>
            </div>
        </div>

        <div class="analyze-layout">
            <div class="stack">
                <section class="card card--pad reveal" data-slot="main"></section>
                <div class="alert alert--info reveal">
                    ${icon("info")}
                    <div class="small">
                        <strong>Privacidad:</strong> SACM consulta los servicios externos solo con el <em>hash</em> del archivo; el contenido no sale de tu
                        servidor${engines.find((e) => e.id === "virustotal" && e.enabled) ? ", salvo que el administrador active el envío a VirusTotal" : ""}.
                        Las muestras se guardan neutralizadas para que no puedan ejecutarse.
                    </div>
                </div>
            </div>

            <aside class="card reveal">
                <div class="card__header">
                    <div>
                        <div class="card__title">${icon("layers")} Motores de análisis</div>
                        <div class="card__subtitle">${engines.filter((e) => e.enabled).length} de ${engines.length} activos</div>
                    </div>
                </div>
                <div class="card__body">
                    <div class="engine-list">
                        ${engines.map((engine) => html`
                            <div class="engine-item ${engine.enabled ? "" : "is-off"}">
                                <span class="engine-item__logo">${icon(ENGINE_ICONS[engine.id] || "shield")}</span>
                                <div style="min-width:0;flex:1">
                                    <div class="strong">${engine.name}</div>
                                    <div class="subtle small">${engine.description}</div>
                                </div>
                                <span class="status-dot ${engine.enabled ? "status-dot--on" : "status-dot--off"}">${engine.enabled ? "Activo" : "Inactivo"}</span>
                            </div>`)}
                    </div>
                </div>
            </aside>
        </div>
    `);

    const main = $('[data-slot="main"]', el);

    function showPicker() {
        mount(main, html`
            <label class="dropzone" data-slot="dropzone">
                <input type="file" data-slot="input">
                <span class="dropzone__icon">${icon("upload", "icon--xl")}</span>
                <span class="dropzone__title">Arrastra un archivo aquí</span>
                <span class="muted">o haz clic para buscarlo · máximo ${maxUploadMb} MB</span>
                <span class="chips" style="justify-content:center;margin-top:8px">
                    ${["EXE", "DLL", "PDF", "DOCX", "XLSM", "ZIP", "PS1", "JS", "APK"].map((t) => html`<span class="chip">${t}</span>`)}
                </span>
            </label>
            <div class="row row--between row--wrap" style="margin-top:16px">
                <span class="subtle small">¿Quieres ver una detección? Usa el archivo de prueba estándar de los antivirus.</span>
                <button class="btn btn--sm" data-action="eicar">${icon("flask", "icon--sm")} Probar con EICAR</button>
            </div>
        `);

        const zone = $('[data-slot="dropzone"]', main);
        const input = $('[data-slot="input"]', main);
        input.addEventListener("change", () => input.files[0] && choose(input.files[0]));
        ["dragenter", "dragover"].forEach((type) => zone.addEventListener(type, (event) => {
            event.preventDefault();
            zone.classList.add("is-dragging");
        }));
        ["dragleave", "drop"].forEach((type) => zone.addEventListener(type, (event) => {
            event.preventDefault();
            zone.classList.remove("is-dragging");
        }));
        zone.addEventListener("drop", (event) => event.dataTransfer.files[0] && choose(event.dataTransfer.files[0]));
    }

    function choose(file) {
        if (file.size > maxUploadMb * 1024 * 1024) {
            toast.error(`El archivo pesa ${formatBytes(file.size)} y el máximo es ${maxUploadMb} MB`);
            return;
        }
        selected = file;
        mount(main, html`
            <div class="upload-file">
                <span class="dropzone__icon" style="width:52px;height:52px;border-radius:16px;animation:none">${icon("file-code", "icon--lg")}</span>
                <div style="flex:1;min-width:0">
                    <div class="strong truncate">${file.name}</div>
                    <div class="subtle small">${formatBytes(file.size)} · ${file.type || "tipo desconocido"}</div>
                </div>
                <button class="btn btn--ghost btn--icon" data-action="reset" aria-label="Quitar archivo">${icon("x")}</button>
            </div>
            <div class="row" style="margin-top:20px;justify-content:flex-end">
                <button class="btn" data-action="reset">Cambiar archivo</button>
                <button class="btn btn--primary btn--lg" data-action="start">${icon("zap")} Iniciar análisis</button>
            </div>
        `);
    }

    function setStep(index) {
        main.querySelectorAll(".step").forEach((step, i) => {
            step.classList.toggle("is-done", i < index);
            step.classList.toggle("is-active", i === index);
            const iconEl = step.querySelector(".step__icon");
            mount(iconEl, i < index ? icon("check", "icon--sm") : "");
        });
    }

    async function start() {
        const file = selected;
        mount(main, html`
            <div class="row row--between" style="margin-bottom:16px">
                <div style="min-width:0">
                    <div class="subtle small">Analizando</div>
                    <div class="strong truncate">${file.name}</div>
                </div>
                <span class="badge badge--info badge--dot badge--running">En curso</span>
            </div>
            <div class="progress" style="margin-bottom:20px"><div class="progress__bar" data-slot="bar"></div></div>
            <div class="steps">${STEPS.map((s) => html`<div class="step"><span class="step__icon"></span><span>${s.label}</span></div>`)}</div>
        `);
        setStep(0);
        const bar = $('[data-slot="bar"]', main);

        const form = new FormData();
        form.append("file", file);

        let result;
        try {
            result = await upload("/analyses", form, (percent) => { bar.style.width = `${percent * 0.3}%`; });
        } catch (error) {
            toast.error(error.message);
            showPicker();
            return;
        }

        // Los pasos avanzan mientras el servidor trabaja; el resultado real llega por consulta periódica
        let step = 1;
        let progress = 30;
        setStep(step);
        ticker = setInterval(() => {
            progress = Math.min(92, progress + 4);
            bar.style.width = `${progress}%`;
            if (step < STEPS.length - 1 && progress > 30 + step * 15) setStep(++step);
        }, 350);

        polling = setInterval(async () => {
            try {
                const status = await api.get(`/analyses/${result.analysis.id}/status`);
                if (status.status === "completed" || status.status === "failed") {
                    clearInterval(polling);
                    clearInterval(ticker);
                    polling = null;
                    bar.style.width = "100%";
                    setStep(STEPS.length);
                    setTimeout(() => showResult(result.analysis.id, status, file), 450);
                }
            } catch (error) {
                clearInterval(polling);
                clearInterval(ticker);
                toast.error(error.message);
            }
        }, 900);
    }

    function showResult(id, status, file) {
        if (status.status === "failed") {
            mount(main, html`<div class="alert alert--danger">${icon("alert-triangle")}<div>No se pudo completar el análisis. <a href="#/analyses/${id}">Ver detalles</a></div></div>`);
            return;
        }
        const messages = {
            malicious: "Este archivo es peligroso. No lo abras y elimínalo de tu equipo.",
            suspicious: "El archivo tiene características sospechosas. Un analista puede revisarlo.",
            clean: "No se encontraron señales de amenaza en este archivo."
        };
        mount(main, html`
            <div class="row reveal" style="gap:32px;flex-wrap:wrap;justify-content:center">
                ${gauge(status.riskScore)}
                <div style="flex:1;min-width:240px">
                    ${verdictBadge(status.verdict)}
                    <h2 style="margin-top:12px" class="break">${file.name}</h2>
                    <p class="muted" style="margin-top:8px">${messages[status.verdict]}</p>
                    <div class="row row--wrap" style="margin-top:20px">
                        <a class="btn btn--primary" href="#/analyses/${id}">${icon("eye")} Ver reporte completo</a>
                        <button class="btn" data-action="reset">${icon("upload")} Analizar otro</button>
                    </div>
                </div>
            </div>
        `);
        animateGauges(main);
        animateCounters(main);
    }

    const offActions = onAction(el, {
        reset: () => {
            selected = null;
            showPicker();
        },
        start: () => selected && start(),
        eicar: () => choose(new File([EICAR_TEST], "eicar_prueba.com", { type: "application/octet-stream" }))
    });

    showPicker();

    return () => {
        offActions();
        if (polling) clearInterval(polling);
        if (ticker) clearInterval(ticker);
    };
}
