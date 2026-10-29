/**
 * Combina todas las señales en un puntaje de riesgo explicable (0-100).
 * Cada punto sumado o restado queda registrado como una "razón" visible para el analista.
 */

const RULE_POINTS = { critical: 70, high: 40, medium: 20, low: 8 };
const MALICIOUS_AT = 70;
const SUSPICIOUS_AT = 30;
const NON_COMPRESSED = ["executable", "script", "text", "binary"];

function clamp(value, min = 0, max = 100) {
    return Math.max(min, Math.min(max, Math.round(value)));
}

function computeScore({ fileInfo, entropy, pe, ruleMatches, engines }) {
    const reasons = [];
    let points = 0;
    let floor = 0;

    const add = (source, label, impact, severity) => {
        points += impact;
        reasons.push({ source, label, impact, severity });
    };
    const setFloor = (source, label, value, severity = "critical") => {
        floor = Math.max(floor, value);
        reasons.push({ source, label, impact: `≥${value}`, severity });
    };

    // --- Reglas (con rendimiento decreciente para no inflar el puntaje) ---
    const eicar = ruleMatches.find((r) => r.ruleId === "eicar_test_file");
    if (eicar) setFloor("sacm_rules", "Archivo de prueba EICAR detectado", 100);

    let rulePoints = 0;
    ruleMatches.filter((r) => r !== eicar).forEach((rule, index) => {
        const value = Math.round(RULE_POINTS[rule.severity] / (1 + index * 0.35));
        rulePoints += value;
        reasons.push({ source: "sacm_rules", label: rule.name, impact: value, severity: rule.severity });
    });
    points += Math.min(rulePoints, 90);

    // --- Tipo de archivo ---
    if (fileInfo.mismatch?.severity === "critical") {
        setFloor("sacm_static", fileInfo.mismatch.message, 75);
    } else if (fileInfo.mismatch) {
        add("sacm_static", fileInfo.mismatch.message, 15, fileInfo.mismatch.severity);
    }
    if (fileInfo.doubleExtension) {
        const label = fileInfo.rtlo ? "Nombre con carácter de inversión (RTLO) para ocultar la extensión" : "Doble extensión para engañar al usuario";
        if (["executable", "script"].includes(fileInfo.category)) setFloor("sacm_static", `${label} en un archivo ejecutable`, 75);
        else add("sacm_static", label, 40, "high");
    }

    // --- Ejecutables PE ---
    if (pe?.valid) {
        if (pe.sections.some((s) => s.writable && s.executable)) add("sacm_static", "Sección PE escribible y ejecutable a la vez", 15, "high");
        if (pe.packers.length) add("sacm_static", `Empaquetado con ${pe.packers.join(", ")}`, 15, "medium");
        if (pe.sections.some((s) => s.executable && s.entropy > 7.2)) add("sacm_static", "Código ejecutable con entropía muy alta (posible cifrado)", 12, "medium");
        if (pe.importCount === 0) add("sacm_static", "El ejecutable no declara importaciones (carga APIs en tiempo de ejecución)", 10, "medium");
        if (pe.futureTimestamp) add("sacm_static", "Fecha de compilación en el futuro (falsificada)", 5, "low");
    } else if (NON_COMPRESSED.includes(fileInfo.category) && entropy.overall > 7.5) {
        add("sacm_static", `Entropía muy alta (${entropy.overall}) para este tipo de archivo`, 10, "medium");
    }

    // --- Inteligencia externa ---
    const vt = engines.virustotal;
    if (vt?.status === "ok") {
        const m = vt.detections || 0;
        if (m >= 10) setFloor("virustotal", `${m} antivirus lo detectan en VirusTotal`, 92);
        else if (m >= 5) setFloor("virustotal", `${m} antivirus lo detectan en VirusTotal`, 85);
        else if (m >= 3) setFloor("virustotal", `${m} antivirus lo detectan en VirusTotal`, 72, "high");
        else if (m >= 1) add("virustotal", `${m} antivirus lo marcan en VirusTotal`, 25, "medium");
        else if (vt.total >= 30) add("virustotal", `Ningún antivirus de ${vt.total} lo detecta`, -25, "info");
    }

    const mb = engines.malwarebazaar;
    if (mb?.status === "ok") setFloor("malwarebazaar", `Muestra registrada en MalwareBazaar${mb.family ? ` (${mb.family})` : ""}`, 95);

    const circl = engines.circl_hashlookup;
    if (circl?.status === "ok") {
        if (circl.verdict === "malicious") setFloor("circl_hashlookup", circl.summary, 90);
        else add("circl_hashlookup", "Archivo legítimo conocido (NSRL / repositorios oficiales)", -35, "info");
    }

    const urlhaus = engines.urlhaus;
    if (urlhaus?.status === "ok" && urlhaus.detections > 0) {
        setFloor("urlhaus", `${urlhaus.detections} dominio(s)/IP del archivo distribuyen malware`, 65, "high");
        add("urlhaus", "Infraestructura maliciosa conocida", Math.min(urlhaus.detections, 2) * 15, "high");
    }

    const score = clamp(Math.max(floor, points));
    const verdict = score >= MALICIOUS_AT ? "malicious" : score >= SUSPICIOUS_AT ? "suspicious" : "clean";

    // --- Confianza: depende de cuántas fuentes respondieron ---
    let confidence = 55;
    if (vt?.status === "ok") confidence += 25;
    else if (vt?.status === "not_found") confidence += 5;
    if (mb && ["ok", "not_found"].includes(mb.status)) confidence += 8;
    if (circl && ["ok", "not_found"].includes(circl.status)) confidence += 5;
    if (ruleMatches.length >= 2) confidence += 7;
    if (eicar || mb?.status === "ok") confidence = 99;

    // --- Familia y categoría ---
    const topRule = ruleMatches.find((r) => r.family);
    const family = eicar ? "EICAR-Test-File" : mb?.family || vt?.family || (verdict !== "clean" ? topRule?.family : null) || null;
    const category = eicar ? "test" : vt?.category || (verdict !== "clean" ? ruleMatches[0]?.category : null) || null;

    return { score, verdict, confidence: clamp(confidence, 0, 99), family, category, reasons };
}

module.exports = { computeScore };
