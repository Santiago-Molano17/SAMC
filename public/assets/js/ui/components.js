/** Piezas de interfaz reutilizables (todas devuelven plantillas seguras) */
import { html, raw } from "../core/dom.js";
import { icon } from "./icons.js";
import {
    VERDICT, STATUS, SEVERITY, ROLE, CASE_STATUS, PRIORITY, initials, toneFor, formatBytes, timeAgo, formatNumber
} from "../core/format.js";

export function verdictBadge(verdict, { reviewed = false } = {}) {
    const info = VERDICT[verdict] || VERDICT.unknown;
    return html`<span class="badge badge--${verdict || "pending"}" title="${reviewed ? "Veredicto confirmado por un analista" : ""}">
        ${icon(info.icon, "icon--sm")} ${info.label}${reviewed ? html` ${icon("check", "icon--sm")}` : ""}
    </span>`;
}

export function statusBadge(status) {
    const tone = { queued: "pending", running: "info", completed: "success", failed: "danger" }[status] || "pending";
    return html`<span class="badge badge--dot badge--${tone} ${status === "running" || status === "queued" ? "badge--running" : ""}">${STATUS[status] || status}</span>`;
}

export const severityBadge = (severity) => html`<span class="badge badge--${severity}">${SEVERITY[severity] || severity}</span>`;

export function roleBadge(role) {
    const tone = { SUPER_ADMIN: "accent", ADMIN: "danger", ANALYST: "primary", USER: "outline" }[role] || "outline";
    return html`<span class="badge badge--${tone}">${ROLE[role] || role}</span>`;
}

export function caseStatusBadge(status) {
    const tone = { open: "info", investigating: "warning", contained: "accent", closed: "success" }[status];
    return html`<span class="badge badge--dot badge--${tone}">${CASE_STATUS[status]}</span>`;
}

export const priorityBadge = (priority) => html`<span class="badge badge--${priority}">${icon("flag", "icon--sm")} ${PRIORITY[priority]}</span>`;

export function avatar(person, size = "") {
    const name = person?.fullName || "?";
    const sizeClass = size ? `avatar--${size}` : "";
    return person?.avatarUrl
        ? html`<span class="avatar ${sizeClass}"><img src="${person.avatarUrl}" alt="${name}" loading="lazy"></span>`
        : html`<span class="avatar ${sizeClass}" data-tone="${toneFor(name)}" aria-label="${name}">${initials(name)}</span>`;
}

export function personCell(person, sub) {
    if (!person) return html`<span class="subtle">—</span>`;
    return html`<span class="person">${avatar(person, "xs")}<span class="person__name">${person.fullName}</span>${sub ? html`<span class="subtle small">${sub}</span>` : ""}</span>`;
}

export function riskColor(score) {
    if (score >= 70) return "var(--danger)";
    if (score >= 30) return "var(--warning)";
    return "var(--success)";
}

export function riskBar(score) {
    const value = Math.max(0, Math.min(100, Number(score) || 0));
    return html`<div class="risk-bar">
        <div class="risk-bar__track"><div class="risk-bar__fill" style="width:${value}%;background-position:${-value * 3}px 0"></div></div>
        <span class="risk-bar__value" style="color:${raw(riskColor(value))}">${value}</span>
    </div>`;
}

export function gauge(score, label = "Riesgo") {
    const value = Math.max(0, Math.min(100, Number(score) || 0));
    const radius = 78;
    const circumference = 2 * Math.PI * radius;
    return html`<div class="gauge" data-gauge="${value}">
        <svg viewBox="0 0 180 180">
            <defs>
                <linearGradient id="gauge-gradient" x1="0" x2="1" y1="0" y2="1">
                    <stop offset="0%" stop-color="${raw(riskColor(value))}" stop-opacity="0.65"/>
                    <stop offset="100%" stop-color="${raw(riskColor(value))}"/>
                </linearGradient>
            </defs>
            <circle class="gauge__track" cx="90" cy="90" r="${radius}" fill="none" stroke-width="14"/>
            <circle class="gauge__value" cx="90" cy="90" r="${radius}" fill="none" stroke="url(#gauge-gradient)" stroke-width="14"
                stroke-dasharray="${circumference}" stroke-dashoffset="${circumference}" data-target="${circumference * (1 - value / 100)}"/>
        </svg>
        <div class="gauge__center">
            <span class="gauge__number" data-count="${value}" style="color:${raw(riskColor(value))}">0</span>
            <span class="gauge__label">${label}</span>
        </div>
    </div>`;
}

/** Inicia la animación de los medidores circulares dentro de root */
export function animateGauges(root) {
    requestAnimationFrame(() => {
        root.querySelectorAll(".gauge__value[data-target]").forEach((circle) => {
            circle.style.strokeDashoffset = circle.dataset.target;
        });
    });
}

const FILE_ICONS = { pe: "cpu", elf: "cpu", macho: "cpu", msi: "cpu", apk: "cpu", jar: "cpu", pdf: "file", docx: "file", xlsx: "file", pptx: "file", ole: "file", zip: "layers", rar: "layers", "7z": "layers" };

export function fileCell(item, href) {
    return html`<div class="cell-file">
        <div class="cell-file__icon">${icon(FILE_ICONS[item.fileType] || "file-code")}</div>
        <div style="min-width:0">
            <div class="cell-file__name" title="${item.originalName}">${href ? html`<a href="${href}">${item.originalName}</a>` : item.originalName}</div>
            <div class="cell-file__meta">${formatBytes(item.size)} · ${(item.fileType || "—").toUpperCase()} · <span class="mono">${(item.sha256 || "").slice(0, 12)}</span></div>
        </div>
    </div>`;
}

export function kpiCard({ label, value, iconName, tone = "", foot = "", decimals = 0, suffix = "" }) {
    return html`<div class="card kpi kpi--${tone}">
        <div class="kpi__top">
            <span class="kpi__label">${label}</span>
            <span class="kpi__icon">${icon(iconName)}</span>
        </div>
        <div class="kpi__value" data-count="${value}" data-decimals="${decimals}" data-suffix="${suffix}">0</div>
        <div class="kpi__foot">${foot}</div>
    </div>`;
}

export function trend(delta, { inverse = false, suffix = "%" } = {}) {
    const value = Number(delta) || 0;
    if (value === 0) return html`<span class="trend trend--neutral">= sin cambio</span>`;
    const up = value > 0;
    const bad = inverse ? !up : up;
    return html`<span class="trend trend--${bad ? "up" : "down"}">${icon(up ? "arrow-up" : "arrow-down", "icon--sm")}${formatNumber(Math.abs(value), 1)}${suffix}</span>`;
}

export function emptyState({ iconName = "inbox", title, message = "", action = "" }) {
    return html`<div class="empty">
        <div class="empty__icon">${icon(iconName, "icon--lg")}</div>
        <div class="empty__title">${title}</div>
        ${message ? html`<p>${message}</p>` : ""}
        ${action}
    </div>`;
}

export function skeletonRows(rows = 6, cols = 5) {
    return html`${Array.from({ length: rows }, () => html`<tr>${Array.from({ length: cols }, () => html`<td><div class="skeleton skeleton--text"></div></td>`)}</tr>`)}`;
}

export const pageLoader = () => html`<div class="loader"><div class="spinner"></div></div>`;

export function pagination(result) {
    if (!result || result.total === 0) return "";
    const from = (result.page - 1) * result.pageSize + 1;
    const to = Math.min(result.total, result.page * result.pageSize);
    return html`<div class="pagination">
        <span>Mostrando <strong>${from}–${to}</strong> de <strong>${formatNumber(result.total)}</strong></span>
        <div class="row">
            <button class="btn btn--sm" data-action="page" data-page="${result.page - 1}" ${result.page <= 1 ? raw("disabled") : ""}>${icon("chevron-left", "icon--sm")} Anterior</button>
            <span class="small">Página ${result.page} de ${result.totalPages}</span>
            <button class="btn btn--sm" data-action="page" data-page="${result.page + 1}" ${result.page >= result.totalPages ? raw("disabled") : ""}>Siguiente ${icon("chevron-right", "icon--sm")}</button>
        </div>
    </div>`;
}

export function barList(items, { valueKey = "total", labelKey = "label", tone = "", format = (v) => formatNumber(v), href } = {}) {
    if (!items?.length) return emptyState({ iconName: "bar-chart", title: "Sin datos en este periodo" });
    const max = Math.max(...items.map((i) => i[valueKey]), 1);
    return html`<div class="bars">${items.map((item, index) => html`
        <div class="bars__item">
            <span class="bars__label" title="${item[labelKey]}">${href ? html`<a href="${href(item)}">${item[labelKey]}</a>` : item[labelKey]}</span>
            <span class="bars__value">${format(item[valueKey], item)}</span>
            <div class="bars__track"><div class="bars__fill ${tone ? `bars__fill--${typeof tone === "function" ? tone(item) : tone}` : ""}" style="width:${(item[valueKey] / max) * 100}%;animation-delay:${index * 60}ms"></div></div>
        </div>`)}
    </div>`;
}

export const relative = (value) => html`<span title="${value ? new Date(value).toLocaleString("es-CO") : ""}">${timeAgo(value)}</span>`;
