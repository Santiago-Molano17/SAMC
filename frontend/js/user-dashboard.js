const API_URL = "http://localhost:5000/api";

// Escapa texto controlado por usuarios antes de insertarlo con innerHTML (evita XSS almacenado)
function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

let user = null;
let currentAnalysis = null;
let analysesCache = [];

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

    // Mostrar usuario
    document.getElementById("username").textContent = user.fullname;
    document.getElementById("userDisplay").textContent = user.email;

    // Event listeners
    setupEventListeners();
    loadMyAnalysis();
});

// =========================
// SETUP EVENT LISTENERS
// =========================

function setupEventListeners() {
    // Navegación de secciones
    document.querySelectorAll("[data-section]").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const section = e.currentTarget.dataset.section;
            showSection(section);

            // Update active nav
            document.querySelectorAll("[data-section]").forEach(l => l.classList.remove("active"));
            e.currentTarget.classList.add("active");
        });
    });

    // Upload area
    const uploadArea = document.getElementById("uploadArea");
    const fileInput = document.getElementById("file");

    uploadArea.addEventListener("click", () => fileInput.click());

    uploadArea.addEventListener("dragover", (e) => {
        e.preventDefault();
        uploadArea.classList.add("dragover");
    });

    uploadArea.addEventListener("dragleave", () => {
        uploadArea.classList.remove("dragover");
    });

    uploadArea.addEventListener("drop", (e) => {
        e.preventDefault();
        uploadArea.classList.remove("dragover");
        fileInput.files = e.dataTransfer.files;
        updateFileDisplay();
    });

    fileInput.addEventListener("change", updateFileDisplay);

    // Upload form
    document.getElementById("uploadForm").addEventListener("submit", uploadFile);

    // Code analysis
    document.getElementById("analyzeCodeBtn").addEventListener("click", analyzeCode);
    setupSampleButtons();

    // Simulator
    document.getElementById("simulatorSelect").addEventListener("change", loadSimulator);
    document.getElementById("playSimulatorBtn").addEventListener("click", playSimulation);
}

// =========================
// MOSTRAR SECCIÓN
// =========================

function showSection(section) {
    document.querySelectorAll(".section-content").forEach(s => s.classList.add("d-none"));
    document.getElementById(`${section}-section`).classList.remove("d-none");

    const titles = {
        "uploads": "Cargar Archivo",
        "analysis": "Mis Análisis",
        "simulator": "Simulador"
    };

    document.getElementById("pageTitle").textContent = titles[section];
}

// =========================
// ACTUALIZAR DISPLAY DEL ARCHIVO
// =========================

function updateFileDisplay() {
    const file = document.getElementById("file").files[0];
    if (file) {
        document.getElementById("fileSelected").classList.remove("d-none");
        document.getElementById("fileName").textContent = `${file.name} (${formatFileSize(file.size)})`;
    }
}

// =========================
// CARGAR ARCHIVO
// =========================

async function uploadFile(e) {
    e.preventDefault();

    const file = document.getElementById("file").files[0];
    if (!file) {
        alert("Selecciona un archivo");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
        document.getElementById("uploadForm").style.display = "none";
        document.getElementById("analyzingProgress").classList.remove("d-none");

        const response = await fetch(`${API_URL}/files/upload`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            },
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Error en la carga");
        }

        currentAnalysis = data.analysis;
        showAnalysisResult(data.analysis, file.name);
        loadMyAnalysis();

    } catch (error) {
        alert(`Error: ${error.message}`);
    } finally {
        document.getElementById("uploadForm").style.display = "block";
        document.getElementById("analyzingProgress").classList.add("d-none");
        document.getElementById("file").value = "";
        document.getElementById("fileSelected").classList.add("d-none");
    }
}

// =========================
// ANALIZAR CÓDIGO
// =========================

async function analyzeCode() {
    const code = document.getElementById("codeInput").value;
    if (!code.trim()) {
        alert("Ingresa código para analizar");
        return;
    }

    // Crear blob del código
    const blob = new Blob([code], { type: "text/plain" });
    const file = new File([blob], "code.txt", { type: "text/plain" });

    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch(`${API_URL}/files/upload`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            },
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        currentAnalysis = data.analysis;
        showAnalysisResult(data.analysis, "Código analizado");

    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// =========================
// MOSTRAR RESULTADO
// =========================

function normalizeAnalysis(analysis, filename = "Archivo analizado") {
    const risk = Number.isFinite(Number(analysis.risk_percentage)) ? Number(analysis.risk_percentage) : 0;
    const confidenceValue = Number(analysis.detection_confidence);
    const confidence = Number.isFinite(confidenceValue)
        ? Math.max(0, Math.min(100, confidenceValue))
        : (risk === 0 ? 100 : Math.max(20, Math.min(95, risk)));

    return {
        ...analysis,
        malware_type: analysis.malware_type || (risk > 0 ? "Suspicious" : "Clean"),
        risk_level: analysis.risk_level || (risk >= 80 ? "Critical" : risk >= 60 ? "High" : risk >= 40 ? "Medium" : "Low"),
        risk_percentage: Math.max(0, Math.min(100, risk)),
        detection_confidence: confidence,
        vulnerabilities: Array.isArray(analysis.vulnerabilities) ? analysis.vulnerabilities : ["Sin vulnerabilidades detectadas"],
        behaviors: Array.isArray(analysis.behaviors) ? analysis.behaviors : [],
        affected_system_areas: Array.isArray(analysis.affected_system_areas) ? analysis.affected_system_areas : [],
        detected_capabilities: Array.isArray(analysis.detected_capabilities) ? analysis.detected_capabilities : [],
        recommendation: analysis.recommendation || "No se generó recomendación.",
        file_info: {
            name: analysis.file_info?.name || filename,
            size: analysis.file_info?.size || 0,
            type: analysis.file_info?.type || "text/plain"
        }
    };
}

function showAnalysisResult(analysis, filename) {
    analysis = normalizeAnalysis(analysis, filename);
    let riskColor = "success";
    let riskIcon = "check-circle";
    const riskWidth = Math.max(analysis.risk_percentage, 4);
    const confidenceWidth = Math.max(analysis.detection_confidence, 4);

    if (analysis.risk_percentage >= 80) {
        riskColor = "danger";
        riskIcon = "times-circle";
    } else if (analysis.risk_percentage >= 60) {
        riskColor = "warning";
        riskIcon = "exclamation-circle";
    }

    const behaviorsHtml = (analysis.behaviors || [])
        .map(b => `<li class="list-group-item">${b}</li>`)
        .join("");

    const capabilitiesHtml = (analysis.detected_capabilities || [])
        .map(c => `<span class="badge bg-danger me-2 mb-2">${c}</span>`)
        .join("");

    const areasHtml = (analysis.affected_system_areas || [])
        .map(a => `<span class="badge bg-warning text-dark me-2 mb-2">${a}</span>`)
        .join("");

    const resultContent = `
        <div class="alert alert-${riskColor} mb-4">
            <h5 class="mb-2">
                <i class="fas fa-${riskIcon}"></i> ${analysis.malware_type}
            </h5>
            <p class="mb-0">${analysis.recommendation}</p>
        </div>

        <div class="row mb-4">
            <div class="col-md-6">
                <h6>Riesgo</h6>
                <div class="progress mb-2">
                    <div class="progress-bar bg-${riskColor}" style="width: ${riskWidth}%">
                        ${analysis.risk_percentage}%
                    </div>
                </div>
                <p class="small text-muted">${analysis.risk_level}</p>
            </div>
            <div class="col-md-6">
                <h6>Confianza de Detección</h6>
                <div class="progress mb-2">
                    <div class="progress-bar bg-info" style="width: ${confidenceWidth}%">
                        ${analysis.detection_confidence}%
                    </div>
                </div>
            </div>
        </div>

        <div class="mb-4">
            <h6>Vulnerabilidades Detectadas:</h6>
            <ul class="list-group small">
                ${analysis.vulnerabilities.map(v => `<li class="list-group-item">${v}</li>`).join("")}
            </ul>
        </div>

        ${capabilitiesHtml ? `
            <div class="mb-4">
                <h6>Capacidades Detectadas:</h6>
                ${capabilitiesHtml}
            </div>
        ` : ""}

        ${areasHtml ? `
            <div class="mb-4">
                <h6>Áreas del Sistema Afectadas:</h6>
                ${areasHtml}
            </div>
        ` : ""}

        ${behaviorsHtml ? `
            <div class="mb-4">
                <h6>Comportamientos Sospechosos:</h6>
                <ul class="list-group small">
                    ${behaviorsHtml}
                </ul>
            </div>
        ` : ""}

        <div class="alert alert-info small">
            <strong>Información del Archivo:</strong><br>
            Nombre: ${escapeHtml(filename)}<br>
            Tipo: ${escapeHtml(analysis.file_info.type)}<br>
            Tamaño: ${formatFileSize(analysis.file_info.size)}
        </div>
    `;

    document.getElementById("resultContent").innerHTML = resultContent;
    new bootstrap.Modal(document.getElementById("resultModal")).show();
}

// =========================
// CARGAR MIS ANÁLISIS
// =========================

async function loadMyAnalysis() {
    try {
        const response = await fetch(`${API_URL}/files/my-analysis`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || data.message || "Error cargando análisis");
        }

        const analysisList = document.getElementById("analysisList");
        const noAnalysis = document.getElementById("noAnalysis");
        const analyses = Array.isArray(data.analysis) ? data.analysis : [];
        analysesCache = analyses;

        if (analyses.length === 0) {
            analysisList.innerHTML = "";
            noAnalysis.classList.remove("d-none");
            return;
        }

        noAnalysis.classList.add("d-none");

        const html = analyses.map(analysis => {
            let riskColor = "success";
            if (analysis.risk_percentage >= 80) riskColor = "danger";
            else if (analysis.risk_percentage >= 60) riskColor = "warning";
            else if (analysis.risk_percentage >= 40) riskColor = "secondary";

            return `
                <div class="col-md-6 mb-3">
                    <div class="card h-100 shadow-sm">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <h6 class="card-title mb-0">${escapeHtml(analysis.original_name)}</h6>
                                <span class="badge bg-${riskColor}">${analysis.risk_level}</span>
                            </div>
                            <p class="text-muted small mb-2">${analysis.malware_type}</p>
                            <div class="progress mb-2">
                                <div class="progress-bar bg-${riskColor}" style="width: ${analysis.risk_percentage}%">
                                    ${analysis.risk_percentage}%
                                </div>
                            </div>
                            <small class="text-muted">${new Date(analysis.analysis_date).toLocaleString()}</small>
                        </div>
                        <div class="card-footer bg-light border-0">
                            <button class="btn btn-sm btn-outline-primary" onclick="viewAnalysis('${analysis.id}')">
                                Ver Detalles
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join("");

        analysisList.innerHTML = html;

        // Load simulator options
        const select = document.getElementById("simulatorSelect");
        select.innerHTML = `<option value="">-- Selecciona un análisis --</option>` +
            analyses.map(a => `<option value="${a.id}">${escapeHtml(a.original_name)}</option>`).join("");

    } catch (error) {
        console.error("Error cargando análisis:", error);
        document.getElementById("analysisList").innerHTML = "";
        document.getElementById("noAnalysis").classList.remove("d-none");
    }
}

// =========================
// VER ANÁLISIS
// =========================

async function viewAnalysis(analysisId) {
    try {
        const response = await fetch(`${API_URL}/files/analysis/${analysisId}`, {
            headers: {
                "Authorization": `Bearer ${localStorage.getItem("token")}`
            }
        });

        const data = await response.json();
        currentAnalysis = data;
        showAnalysisResult(data, data.file_info.name);

    } catch (error) {
        alert("Error cargando análisis");
    }
}

// =========================
// SIMULATOR
// =========================

function loadSimulator() {
    const select = document.getElementById("simulatorSelect");
    if (select.value === "" || !currentAnalysis) {
        document.getElementById("simulatorContent").classList.add("d-none");
        return;
    }

    const analysis = currentAnalysis;
    const simulatorContent = document.getElementById("simulatorContent");

    // Procesos
    const processes = [
        "explorer.exe",
        "svchost.exe",
        "lsass.exe",
        "ntoskrnl.exe",
        "services.exe"
    ];

    const affectedProcesses = document.getElementById("affectedProcesses");
    affectedProcesses.innerHTML = processes.map(p => `
        <a class="list-group-item list-group-item-action" href="#">
            <i class="fas fa-cube"></i> ${p}
        </a>
    `).join("");

    // Archivos
    const files = [
        "C:\\Users\\Documents\\...",
        "C:\\Windows\\System32\\...",
        "C:\\Program Files\\..."
    ];

    const affectedFiles = document.getElementById("affectedFiles");
    affectedFiles.innerHTML = files.map(f => `
        <a class="list-group-item list-group-item-action" href="#">
            <i class="fas fa-lock"></i> ${f}
        </a>
    `).join("");

    simulatorContent.classList.remove("d-none");
}

function playSimulation() {
    if (!currentAnalysis) return;

    const screen = document.getElementById("simulatorScreen");
    const analysis = currentAnalysis;

    // Simulación visual
    let timeline = "<div class='timeline'>";

    timeline += `<div class="timeline-item error">
        <i class="fas fa-virus"></i>
        <p>Malware detectado: ${analysis.malware_type}</p>
        <small>Riesgo: ${analysis.risk_percentage}%</small>
    </div>`;

    (analysis.detected_capabilities || []).forEach((cap, i) => {
        timeline += `<div class="timeline-item">
            <i class="fas fa-triangle-exclamation"></i>
            <p>${cap}</p>
            <small>+${(i + 1) * 2} segundos</small>
        </div>`;
    });

    timeline += `<div class="timeline-item alert">
        <i class="fas fa-shield"></i>
        <p>Sistema comprometido</p>
    </div>`;

    timeline += "</div>";

    screen.innerHTML = timeline;
}

// =========================
// UTILIDADES
// =========================

async function loadSimulator() {
    const select = document.getElementById("simulatorSelect");
    if (select.value === "") {
        document.getElementById("simulatorContent").classList.add("d-none");
        return;
    }

    let analysis = currentAnalysis && currentAnalysis.id === select.value ? currentAnalysis : null;

    if (!analysis) {
        try {
            const response = await fetch(`${API_URL}/files/analysis/${select.value}`, {
                headers: {
                    "Authorization": `Bearer ${localStorage.getItem("token")}`
                }
            });

            analysis = await response.json();
            if (!response.ok) {
                throw new Error(analysis.error || analysis.message || "Error cargando simulación");
            }

            currentAnalysis = analysis;
        } catch (error) {
            alert(error.message);
            document.getElementById("simulatorContent").classList.add("d-none");
            return;
        }
    }

    const impact = buildImpactModel(analysis);

    document.getElementById("affectedProcesses").innerHTML = impact.processes.map(p => `
        <a class="list-group-item list-group-item-action" href="#">
            <i class="fas fa-microchip"></i> ${p}
        </a>
    `).join("");

    document.getElementById("affectedFiles").innerHTML = impact.files.map(f => `
        <a class="list-group-item list-group-item-action" href="#">
            <i class="fas fa-lock"></i> ${f}
        </a>
    `).join("");

    document.getElementById("simulatorScreen").innerHTML = `
        <div class="simulation-summary">
            <h6>${analysis.malware_type || "Amenaza desconocida"}</h6>
            <p>Riesgo estimado: ${analysis.risk_percentage || 0}%</p>
            <p>${impact.summary}</p>
        </div>
    `;

    document.getElementById("simulatorContent").classList.remove("d-none");
}

function setupSampleButtons() {
    const analyzeBtn = document.getElementById("analyzeCodeBtn");
    if (!analyzeBtn || document.getElementById("sampleActions")) return;

    analyzeBtn.insertAdjacentHTML("afterend", `
        <div id="sampleActions" class="sample-actions mt-3">
            <button type="button" class="btn btn-sm btn-outline-danger" data-sample="ransomware">Ransomware demo</button>
            <button type="button" class="btn btn-sm btn-outline-warning" data-sample="spyware">Spyware demo</button>
            <button type="button" class="btn btn-sm btn-outline-info" data-sample="worm">Worm demo</button>
        </div>
    `);

    document.querySelectorAll("[data-sample]").forEach(button => {
        button.addEventListener("click", () => {
            document.getElementById("codeInput").value = getSampleCode(button.dataset.sample);
        });
    });
}

function getSampleCode(type) {
    const samples = {
        ransomware: `// SIMULACION SEGURA - no ejecuta acciones reales
// Marcadores para SACM: ransomware, encrypt, ransom, bitcoin, file_encryption
function demoRansomwareImpact() {
  const objetivos = ["Documents", "Pictures", "Desktop"];
  console.log("encrypt files", objetivos);
  console.log("ransom note: pay bitcoin to decrypt");
}`,
        spyware: `// SIMULACION SEGURA - no captura datos reales
// Marcadores para SACM: spyware, keylog, password, screen, data_exfiltration
function demoSpywareImpact() {
  console.log("keylog password capture screen credentials");
  console.log("data_exfiltration to remote server");
}`,
        worm: `// SIMULACION SEGURA - no toca red real
// Marcadores para SACM: worm, propagate, replicate, network, spread
function demoWormImpact() {
  console.log("network scan");
  console.log("replicate and spread to shared folders");
}`
    };

    return samples[type] || "";
}

function playSimulation() {
    if (!currentAnalysis) return;

    const screen = document.getElementById("simulatorScreen");
    const analysis = currentAnalysis;
    const impact = buildImpactModel(analysis);

    let timeline = "<div class='timeline'>";

    timeline += `<div class="timeline-item error">
        <i class="fas fa-virus"></i>
        <p>Malware detectado: ${analysis.malware_type}</p>
        <small>Riesgo: ${analysis.risk_percentage}%</small>
    </div>`;

    impact.events.forEach((event, i) => {
        timeline += `<div class="timeline-item">
            <i class="fas fa-${event.icon}"></i>
            <p>${event.title}</p>
            <small>${event.detail}</small>
            <small>+${(i + 1) * 2} segundos</small>
        </div>`;
    });

    timeline += `<div class="timeline-item alert">
        <i class="fas fa-shield"></i>
        <p>${impact.summary}</p>
    </div>`;

    timeline += "</div>";
    screen.innerHTML = timeline;
}

function buildImpactModel(analysis) {
    const type = (analysis.malware_type || "").toLowerCase();
    const capabilities = (analysis.detected_capabilities || []).join(" ").toLowerCase();
    const text = `${type} ${capabilities}`;

    const model = {
        summary: "El archivo podría ejecutar acciones sospechosas, consumir recursos y alterar configuraciones del usuario.",
        processes: ["explorer.exe", "svchost.exe", "services.exe"],
        files: ["C:\\Users\\Documents\\*", "C:\\Users\\Downloads\\*", "C:\\Temp\\*"],
        events: [
            { icon: "terminal", title: "Ejecución inicial", detail: "El archivo intenta iniciar procesos secundarios." },
            { icon: "gear", title: "Cambios de configuración", detail: "Se detectan señales de modificación del entorno." }
        ]
    };

    if (text.includes("ransom") || text.includes("encryption") || text.includes("file_encryption")) {
        model.summary = "El malware podría cifrar documentos personales y bloquear el acceso a archivos importantes.";
        model.processes.push("vssadmin.exe", "cipher.exe");
        model.files = ["C:\\Users\\Documents\\*.docx", "C:\\Users\\Pictures\\*.jpg", "C:\\Users\\Desktop\\*.pdf"];
        model.events.push(
            { icon: "folder-closed", title: "Búsqueda de documentos", detail: "Recorre carpetas del usuario para encontrar archivos valiosos." },
            { icon: "lock", title: "Cifrado de archivos", detail: "Los documentos quedarían inaccesibles sin una clave." }
        );
    } else if (text.includes("spy") || text.includes("keylog") || text.includes("exfiltration")) {
        model.summary = "El malware podría espiar actividad, capturar credenciales y enviar información fuera del equipo.";
        model.processes.push("chrome.exe", "powershell.exe");
        model.files = ["C:\\Users\\AppData\\Local\\Google\\Chrome\\User Data\\*", "C:\\Users\\Documents\\contraseñas.txt"];
        model.events.push(
            { icon: "keyboard", title: "Captura de pulsaciones", detail: "Podría registrar contraseñas y mensajes escritos." },
            { icon: "cloud-arrow-up", title: "Exfiltración", detail: "Intenta enviar datos sensibles a un servidor externo." }
        );
    } else if (text.includes("rootkit") || text.includes("kernel") || text.includes("hiding")) {
        model.summary = "El malware podría ocultarse en el sistema y dificultar su eliminación.";
        model.processes.push("ntoskrnl.exe", "lsass.exe");
        model.files = ["C:\\Windows\\System32\\drivers\\*.sys", "C:\\Windows\\System32\\config\\*"];
        model.events.push(
            { icon: "eye-slash", title: "Ocultamiento", detail: "Puede esconder procesos o controladores maliciosos." },
            { icon: "shield-halved", title: "Persistencia profunda", detail: "Busca sobrevivir a reinicios y análisis básicos." }
        );
    } else if (text.includes("worm") || text.includes("propagation") || text.includes("network")) {
        model.summary = "El malware podría propagarse por red y afectar otros equipos conectados.";
        model.processes.push("net.exe", "wscript.exe");
        model.files = ["\\\\Red\\Compartidos\\*", "C:\\Users\\Public\\*"];
        model.events.push(
            { icon: "network-wired", title: "Escaneo de red", detail: "Busca equipos y carpetas compartidas alcanzables." },
            { icon: "share-nodes", title: "Propagación", detail: "Intenta copiarse a otros sistemas." }
        );
    }

    return model;
}

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
