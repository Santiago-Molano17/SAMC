/**
 * Envoltorio de Chart.js con el estilo de SACM.
 * Las gráficas se recrean al cambiar de tema y se destruyen al salir de la página.
 */

const active = new Set();

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export const PALETTE = ["#22d3ee", "#8b5cf6", "#f43f5e", "#f59e0b", "#10b981", "#3b82f6", "#ec4899", "#14b8a6", "#a3e635", "#f97316"];

export const VERDICT_COLORS = {
    malicious: "#f43f5e",
    suspicious: "#f59e0b",
    clean: "#10b981"
};

function applyDefaults() {
    const { Chart } = window;
    Chart.defaults.font.family = css("--font-sans") || "Inter, sans-serif";
    Chart.defaults.font.size = 12;
    Chart.defaults.color = css("--chart-text");
    Chart.defaults.borderColor = css("--chart-grid");
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.pointStyle = "rectRounded";
    Chart.defaults.plugins.legend.labels.boxWidth = 8;
    Chart.defaults.plugins.legend.labels.boxHeight = 8;
    Chart.defaults.plugins.legend.labels.padding = 16;
    Chart.defaults.plugins.tooltip.backgroundColor = css("--surface-solid");
    Chart.defaults.plugins.tooltip.titleColor = css("--text");
    Chart.defaults.plugins.tooltip.bodyColor = css("--text-muted");
    Chart.defaults.plugins.tooltip.borderColor = css("--border-strong");
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 12;
    Chart.defaults.plugins.tooltip.cornerRadius = 10;
    Chart.defaults.plugins.tooltip.boxPadding = 4;
    Chart.defaults.maintainAspectRatio = false;
    Chart.defaults.animation.duration = 900;
    Chart.defaults.animation.easing = "easeOutQuart";
}

/** Degradado vertical para áreas bajo la curva */
export function areaGradient(color) {
    return (context) => {
        const { ctx, chartArea } = context.chart;
        if (!chartArea) return `${color}33`;
        const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        gradient.addColorStop(0, `${color}55`);
        gradient.addColorStop(1, `${color}00`);
        return gradient;
    };
}

export function createChart(canvas, buildConfig) {
    if (!window.Chart || !canvas) return null;
    applyDefaults();
    const entry = { canvas, buildConfig, chart: new window.Chart(canvas, buildConfig()) };
    active.add(entry);
    return entry.chart;
}

export function destroyCharts() {
    for (const entry of active) entry.chart.destroy();
    active.clear();
}

window.addEventListener("themechange", () => {
    applyDefaults();
    for (const entry of active) {
        entry.chart.destroy();
        entry.chart = new window.Chart(entry.canvas, entry.buildConfig());
    }
});

export const axis = ({ stacked = false, beginAtZero = true, grid = true, ticks = {} } = {}) => ({
    stacked,
    beginAtZero,
    grid: { display: grid, drawTicks: false },
    border: { display: false },
    ticks: { padding: 8, ...ticks }
});
