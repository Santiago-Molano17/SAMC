const API_URL = "http://localhost:5000/api";

// Escapa texto controlado por usuarios antes de insertarlo con innerHTML (evita XSS almacenado)
function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

let user = null;
let charts = {};

// =========================
// INICIALIZACIÓN
// =========================

window.addEventListener("DOMContentLoaded", () => {
    const storedUser = localStorage.getItem("user");
    const token = localStorage.getItem("token");

    if (!storedUser || !token) {
        window.location.href = "login.html";
        return;
    }

    user = JSON.parse(storedUser);

    // Validar rol
    if (!["SUPER_ADMIN", "ADMIN", "ANALYST"].includes(user.role)) {
        window.location.href = "user-dashboard.html";
        return;
    }

    // Mostrar usuario
    document.getElementById("username").textContent = user.fullname;
    document.getElementById("userDisplay").textContent = user.email;
    document.getElementById("roleDisplay").textContent = user.role;

    if (user.role === "ANALYST") {
        document.querySelector("[data-bs-target='#newUserModal']")?.classList.add("d-none");
    }

    // Setup
    setupEventListeners();
    loadDashboard();
});

// =========================
// SETUP EVENT LISTENERS
// =========================

function setupEventListeners() {
    // Navegación
    document.querySelectorAll("[data-section]").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const section = e.currentTarget.dataset.section;
            showSection(section);

            document.querySelectorAll("[data-section]").forEach(l => l.classList.remove("active"));
            e.currentTarget.classList.add("active");
        });
    });

    document.getElementById("newUserForm")?.addEventListener("submit", createUser);
    document.getElementById("analysisSearch")?.addEventListener("input", (e) => {
        document.querySelectorAll("#analysisTable tr").forEach(row => {
            row.classList.toggle("d-none", !row.textContent.toLowerCase().includes(e.target.value.toLowerCase()));
        });
    });
}

// =========================
// MOSTRAR SECCIÓN
// =========================

function showSection(section) {
    document.querySelectorAll(".section-content").forEach(s => s.classList.add("d-none"));
    document.getElementById(`${section}-section`).classList.remove("d-none");

    const titles = {
        "dashboard": "Dashboard",
        "analysis": "Gestión de Análisis",
        "users": "Gestión de Usuarios",
        "profiles": "Perfiles",
        "reports": "Reportes",
        "logs": "Logs de Actividad"
    };

    document.getElementById("pageTitle").textContent = titles[section];

    // Cargar datos según la sección
    if (section === "analysis") loadAnalysis();
    else if (section === "users") loadUsers();
    else if (section === "profiles") loadProfiles();
    else if (section === "reports") loadReportSummary();
    else if (section === "logs") loadLogs();
}

// =========================
// LOAD DASHBOARD
// =========================

async function loadDashboard() {
    try {
        const response = await fetch(`${API_URL}/dashboard/stats`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || data.message || "Error cargando dashboard");
        }

        // Actualizar stats
        document.getElementById("totalAnalysis").textContent = data.totalAnalysis || 0;
        document.getElementById("totalUsers").textContent = data.totalUsers || 0;
        document.getElementById("criticalCount").textContent = data.criticalRisk || 0;

        document.getElementById("highCount").textContent = data.highRisk || 0;

        // Llenar tabla de análisis recientes
        loadRecentAnalysis(data.recentAnalysis || []);

        // Crear gráficos
        createCharts(data);

    } catch (error) {
        console.error("Error cargando dashboard:", error);
    }
}

// =========================
// CARGAR ANÁLISIS RECIENTES
// =========================

function loadRecentAnalysis(analysis) {
    const table = document.getElementById("recentAnalysisTable");
    
    if (analysis.length === 0) {
        table.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Sin análisis recientes</td></tr>`;
        return;
    }

    table.innerHTML = analysis.map(a => {
        let badgeClass = "success";
        if (a.risk_level === "Critical") badgeClass = "danger";
        else if (a.risk_level === "High") badgeClass = "warning";

        return `
            <tr>
                <td>${escapeHtml(a.original_name || "N/A")}</td>
                <td>${escapeHtml(a.user_email || "N/A")}</td>
                <td>${a.malware_type || "N/A"}</td>
                <td><span class="badge bg-${badgeClass}">${a.risk_level || "N/A"}</span></td>
                <td>${a.risk_percentage || 0}%</td>
                <td><small>${new Date(a.analysis_date).toLocaleString()}</small></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewAnalysisDetail('${a.id}')">
                        Ver
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

// =========================
// CREAR GRÁFICOS
// =========================

function createCharts(data) {
    // Gráfico de tipos de malware
    const malwareCtx = document.getElementById("malwareChart");
    if (malwareCtx && !charts.malware) {
        charts.malware = new Chart(malwareCtx, {
            type: "doughnut",
            data: {
                labels: ["Trojan", "Ransomware", "Spyware", "Worm", "Rootkit", "Otros"],
                datasets: [{
                    data: [25, 20, 18, 15, 12, 10],
                    backgroundColor: [
                        "#dc3545",
                        "#fd7e14",
                        "#ffc107",
                        "#17a2b8",
                        "#6f42c1",
                        "#e83e8c"
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: "bottom"
                    }
                }
            }
        });
    }

    // Gráfico de niveles de riesgo
    const riskCtx = document.getElementById("riskChart");
    if (riskCtx && !charts.risk) {
        charts.risk = new Chart(riskCtx, {
            type: "bar",
            data: {
                labels: ["Critical", "High", "Medium", "Low"],
                datasets: [{
                    label: "Cantidad",
                    data: [data.criticalRisk || 0, 15, 25, 45],
                    backgroundColor: [
                        "#dc3545",
                        "#ffc107",
                        "#17a2b8",
                        "#28a745"
                    ]
                }]
            },
            options: {
                responsive: true,
                indexAxis: "y",
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
}

// =========================
// LOAD ANALYSIS
// =========================

function createCharts(data) {
    const malwareStats = data.malwareStats || [];
    const riskStats = data.riskStats || [];
    const malwareLabels = malwareStats.length ? malwareStats.map(item => item.malware_type) : ["Sin datos"];
    const malwareValues = malwareStats.length ? malwareStats.map(item => item.count) : [0];
    const riskOrder = ["Critical", "High", "Medium", "Low", "Sin nivel"];
    const riskMap = Object.fromEntries(riskStats.map(item => [item.risk_level, item.count]));
    const riskLabels = riskOrder.filter(level => riskMap[level] !== undefined);
    const riskValues = riskLabels.map(level => riskMap[level]);

    if (!charts.malware && document.getElementById("malwareChart")) {
        charts.malware = new Chart(document.getElementById("malwareChart"), {
            type: "doughnut",
            data: {
                labels: malwareLabels,
                datasets: [{
                    data: malwareValues,
                    backgroundColor: ["#dc3545", "#fd7e14", "#ffc107", "#17a2b8", "#6f42c1", "#e83e8c", "#20c997", "#0d6efd"]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: "bottom" }
                }
            }
        });
    }

    if (!charts.risk && document.getElementById("riskChart")) {
        charts.risk = new Chart(document.getElementById("riskChart"), {
            type: "bar",
            data: {
                labels: riskLabels.length ? riskLabels : ["Sin datos"],
                datasets: [{
                    label: "Cantidad",
                    data: riskValues.length ? riskValues : [0],
                    backgroundColor: ["#dc3545", "#ffc107", "#17a2b8", "#28a745", "#6c757d"]
                }]
            },
            options: {
                responsive: true,
                indexAxis: "y",
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    if (charts.malware) {
        charts.malware.data.labels = malwareLabels;
        charts.malware.data.datasets[0].data = malwareValues;
        charts.malware.update();
    }

    if (charts.risk) {
        charts.risk.data.labels = riskLabels.length ? riskLabels : ["Sin datos"];
        charts.risk.data.datasets[0].data = riskValues.length ? riskValues : [0];
        charts.risk.update();
    }
}

async function loadAnalysis() {
    try {
        const response = await fetch(`${API_URL}/dashboard/all-analysis`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || "Error cargando análisis");
        const table = document.getElementById("analysisTable");

        if (!data.analysis || data.analysis.length === 0) {
            table.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Sin análisis</td></tr>`;
            return;
        }

        table.innerHTML = data.analysis.map(a => {
            let badgeClass = "success";
            if (a.risk_percentage >= 80) badgeClass = "danger";
            else if (a.risk_percentage >= 60) badgeClass = "warning";

            return `
                <tr>
                    <td>${escapeHtml(a.original_name || "N/A")}</td>
                    <td><small>${escapeHtml(a.fullname || "N/A")}</small></td>
                    <td>${a.malware_type || "N/A"}</td>
                    <td><span class="badge bg-${badgeClass}">${a.risk_level || "N/A"}</span></td>
                    <td>${a.risk_percentage || 0}%</td>
                    <td><small>${new Date(a.analysis_date).toLocaleString()}</small></td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="viewAnalysisDetail('${a.id}')">
                            Detalles
                        </button>
                    </td>
                </tr>
            `;
        }).join("");

    } catch (error) {
        console.error("Error cargando análisis:", error);
        document.getElementById("analysisTable").innerHTML = `<tr><td colspan="7" class="text-center text-danger">${error.message}</td></tr>`;
    }
}

// =========================
// LOAD USERS
// =========================

async function loadUsers() {
    try {
        const response = await fetch(`${API_URL}/dashboard/users`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || "Error cargando usuarios");
        const table = document.getElementById("usersTable");

        if (!data.users || data.users.length === 0) {
            table.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Sin usuarios</td></tr>`;
            return;
        }

        table.innerHTML = data.users.map(u => {
            const badgeClass = u.role_name === "SUPER_ADMIN" ? "danger" : u.role_name === "ADMIN" ? "warning" : "info";

            const actions = user.role === "ANALYST"
                ? `<span class="text-muted small">Solo lectura</span>`
                : `<button class="btn btn-sm btn-outline-danger" onclick="deleteUser('${u.id}')">Eliminar</button>`;

            return `
                <tr>
                    <td>${escapeHtml(u.fullname)}</td>
                    <td><small>${escapeHtml(u.email)}</small></td>
                    <td><span class="badge bg-${badgeClass}">${u.role_name}</span></td>
                    <td><span class="badge bg-success">Activo</span></td>
                    <td><small>${new Date(u.created_at).toLocaleDateString()}</small></td>
                    <td>${actions}</td>
                </tr>
            `;
        }).join("");

    } catch (error) {
        console.error("Error cargando usuarios:", error);
        document.getElementById("usersTable").innerHTML = `<tr><td colspan="6" class="text-center text-danger">${error.message}</td></tr>`;
    }
}

// =========================
// LOAD PROFILES
// =========================

async function loadProfiles() {
    try {
        const response = await fetch(`${API_URL}/dashboard/profiles`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || "Error cargando perfiles");
        const container = document.getElementById("profilesList");

        if (!data.profiles || data.profiles.length === 0) {
            container.innerHTML = `<div class="col-12"><p class="text-muted text-center">Sin perfiles</p></div>`;
            return;
        }

        container.innerHTML = data.profiles.map(p => `
            <div class="col-md-6 col-lg-4 mb-3">
                <div class="card shadow-sm h-100">
                    <div class="card-body">
                        <h6 class="card-title">${escapeHtml(p.fullname)}</h6>
                        <p class="text-muted small mb-2">${escapeHtml(p.email)}</p>
                        <p class="text-muted small mb-3">${escapeHtml(p.department || "Sin departamento")}</p>
                        <span class="badge bg-success">${p.profile_status || "ACTIVE"}</span>
                    </div>
                </div>
            </div>
        `).join("");

    } catch (error) {
        console.error("Error cargando perfiles:", error);
        document.getElementById("profilesList").innerHTML = `<div class="col-12"><p class="text-danger text-center">${error.message}</p></div>`;
    }
}

// =========================
// LOAD LOGS
// =========================

async function loadLogs() {
    try {
        const response = await fetch(`${API_URL}/dashboard/logs`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || "Error cargando logs");
        const table = document.getElementById("logsTable");

        if (!data.logs || data.logs.length === 0) {
            table.innerHTML = `<tr><td colspan="4" class="text-center text-muted">Sin logs</td></tr>`;
            return;
        }

        table.innerHTML = data.logs.map(l => `
            <tr>
                <td><small>${escapeHtml(l.user_email || "Sistema")}</small></td>
                <td><small>${l.action_type}</small></td>
                <td><small>${escapeHtml(l.action_details || "-")}</small></td>
                <td><small>${new Date(l.action_date).toLocaleString()}</small></td>
            </tr>
        `).join("");

    } catch (error) {
        console.error("Error cargando logs:", error);
        document.getElementById("logsTable").innerHTML = `<tr><td colspan="4" class="text-center text-danger">${error.message}</td></tr>`;
    }
}

// =========================
// VIEW ANALYSIS DETAIL
// =========================

async function viewAnalysisDetail(analysisId) {
    try {
        const response = await fetch(`${API_URL}/files/analysis/${analysisId}`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || "Error cargando detalles");

        const fileInfo = data.file_info || {};
        data.file_info = fileInfo;

        const content = `
            <div class="mb-3">
                <h6>Información General</h6>
                <p><strong>Archivo:</strong> ${escapeHtml(fileInfo.name || "N/A")}</p>
                <p><strong>Tipo:</strong> ${escapeHtml(fileInfo.type || "N/A")}</p>
                <p><strong>Tamaño:</strong> ${formatFileSize(data.file_info.size)}</p>
                <p><strong>Fecha de Análisis:</strong> ${new Date(data.analysis_date).toLocaleString()}</p>
            </div>

            <div class="mb-3">
                <h6>Resultado del Análisis</h6>
                <div class="alert alert-${data.risk_percentage >= 80 ? "danger" : data.risk_percentage >= 60 ? "warning" : "success"}">
                    <p><strong>Tipo de Malware:</strong> ${data.malware_type}</p>
                    <p><strong>Nivel de Riesgo:</strong> ${data.risk_level}</p>
                    <p><strong>Riesgo:</strong> ${data.risk_percentage}%</p>
                </div>
            </div>

            <div class="mb-3">
                <h6>Recomendación</h6>
                <p>${data.recommendation}</p>
            </div>

            <div class="mb-3">
                <h6>Vulnerabilidades</h6>
                <ul>
                    ${(data.vulnerabilities || []).map(v => `<li>${v}</li>`).join("")}
                </ul>
            </div>

            <div class="mb-3">
                <h6>Comportamientos Detectados</h6>
                <div>
                    ${(data.behaviors || []).map(b => `<span class="badge bg-warning me-2">${b}</span>`).join("")}
                </div>
            </div>
        `;

        document.getElementById("analysisDetailContent").innerHTML = content;
        new bootstrap.Modal(document.getElementById("viewAnalysisModal")).show();

    } catch (error) {
        alert("Error cargando detalles del análisis");
    }
}

// =========================
// DELETE USER
// =========================

async function deleteUser(userId) {
    if (!confirm("¿Estás seguro de que deseas eliminar este usuario?")) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/users/${userId}`, {
            method: "DELETE",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        if (response.ok) {
            alert("Usuario eliminado");
            loadUsers();
        }

    } catch (error) {
        alert("Error eliminando usuario");
    }
}

// =========================
// GENERATE REPORT
// =========================

function generateReport() {
    loadReportSummary();
}

async function loadReportSummary() {
    const reportContent = document.getElementById("reportContent");
    reportContent.innerHTML = `<p class="text-muted">Cargando reporte...</p>`;

    try {
        const response = await fetch(`${API_URL}/dashboard/reports/summary`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || "Error generando reporte");

        const totals = data.totals || {};
        reportContent.innerHTML = `
            <div class="row g-3 mb-4">
                <div class="col-md-4"><div class="report-metric"><span>Análisis totales</span><strong>${totals.total_analysis || 0}</strong></div></div>
                <div class="col-md-4"><div class="report-metric danger"><span>Críticos/altos</span><strong>${totals.dangerous_analysis || 0}</strong></div></div>
                <div class="col-md-4"><div class="report-metric info"><span>Riesgo promedio</span><strong>${Math.round(totals.avg_risk || 0)}%</strong></div></div>
            </div>
            <div class="row g-4">
                <div class="col-lg-6">
                    <h6>Tipos de malware más vistos</h6>
                    <ul class="list-group small">
                        ${(data.malwareTypes || []).map(item => `
                            <li class="list-group-item d-flex justify-content-between">
                                <span>${item.malware_type}</span><strong>${item.count} (${Math.round(item.avg_risk || 0)}%)</strong>
                            </li>
                        `).join("") || `<li class="list-group-item text-muted">Sin datos</li>`}
                    </ul>
                </div>
                <div class="col-lg-6">
                    <h6>Usuarios con más análisis</h6>
                    <ul class="list-group small">
                        ${(data.topUsers || []).map(item => `
                            <li class="list-group-item d-flex justify-content-between">
                                <span>${escapeHtml(item.fullname || item.email)}</span><strong>${item.total}</strong>
                            </li>
                        `).join("") || `<li class="list-group-item text-muted">Sin datos</li>`}
                    </ul>
                </div>
            </div>
        `;
    } catch (error) {
        reportContent.innerHTML = `<p class="text-danger">No se pudo generar el reporte: ${error.message}</p>`;
    }
}

async function createUser(e) {
    e.preventDefault();

    const form = e.currentTarget;
    const [fullnameInput, emailInput, passwordInput] = form.querySelectorAll("input");
    const roleInput = form.querySelector("select");

    try {
        const response = await fetch(`${API_URL}/dashboard/users`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                fullname: fullnameInput.value,
                email: emailInput.value,
                password: passwordInput.value,
                role: roleInput.value
            })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || "Error creando usuario");

        bootstrap.Modal.getInstance(document.getElementById("newUserModal"))?.hide();
        form.reset();
        loadUsers();
        loadDashboard();
    } catch (error) {
        alert(error.message);
    }
}

// =========================
// UTILIDADES
// =========================

function formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + " " + sizes[i];
}

function logout() {
    localStorage.removeItem("user");
    localStorage.removeItem("token");
    window.location.href = "login.html";
}
