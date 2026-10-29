/**
 * Pruebas del motor de análisis (sin base de datos ni servicios externos).
 * Ejecutar con: npm test
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

process.env.DB_USER = process.env.DB_USER || "test";
process.env.JWT_SECRET = process.env.JWT_SECRET || "x".repeat(40);

const { analyzeBuffer } = require("../src/analysis/analyzer");
const { detectFileType } = require("../src/analysis/static/filetype");
const { shannonEntropy } = require("../src/analysis/static/entropy");
const { extractIndicators } = require("../src/analysis/static/strings");
const { parsePE } = require("../src/analysis/static/pe");
const RULES = require("../src/analysis/rules/definitions");

const analyze = (content, name) => analyzeBuffer(Buffer.isBuffer(content) ? content : Buffer.from(content), name, { external: false });
const EICAR = RULES.find((r) => r.id === "eicar_test_file").patterns[0];

test("detecta el archivo de prueba EICAR como malicioso", async () => {
    const report = await analyze(EICAR, "eicar.com");
    assert.equal(report.score.verdict, "malicious");
    assert.equal(report.score.score, 100);
    assert.equal(report.score.family, "EICAR-Test-File");
});

test("un texto normal es limpio", async () => {
    const report = await analyze("Acta de reunión: presupuesto y cronograma.", "acta.txt");
    assert.equal(report.score.verdict, "clean");
    assert.equal(report.ruleMatches.length, 0);
});

test("un ejecutable disfrazado de imagen es malicioso (T1036.008)", async () => {
    const report = await analyze(Buffer.concat([Buffer.from("MZ"), Buffer.alloc(256)]), "foto.jpg");
    assert.equal(report.fileInfo.type, "pe");
    assert.equal(report.fileInfo.mismatch.severity, "critical");
    assert.equal(report.score.verdict, "malicious");
});

test("la doble extensión en un ejecutable es maliciosa (T1036.007)", async () => {
    const report = await analyze(Buffer.from("MZ stub"), "factura.pdf.exe");
    assert.ok(report.fileInfo.doubleExtension);
    assert.equal(report.score.verdict, "malicious");
});

test("detecta el carácter RTLO que invierte la extensión", () => {
    const info = detectFileType(Buffer.from("MZ"), "factura‮fdp.exe");
    assert.ok(info.rtlo);
    assert.ok(info.doubleExtension);
});

test("identifica tipos por bytes mágicos y no por la extensión", () => {
    assert.equal(detectFileType(Buffer.from("%PDF-1.7"), "x.txt").type, "pdf");
    assert.equal(detectFileType(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "x.pdf").type, "png");
    assert.equal(detectFileType(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]), "x").type, "elf");
});

test("las muestras de demostración resultan sospechosas con su regla", async () => {
    const dir = path.join(__dirname, "..", "samples");
    const expected = { "ransomware_demo.txt": "ransomware_note", "spyware_demo.txt": "spyware_collection", "worm_demo.txt": "worm_propagation" };
    for (const [file, rule] of Object.entries(expected)) {
        const report = await analyze(fs.readFileSync(path.join(dir, file)), file);
        assert.ok(report.ruleMatches.some((m) => m.ruleId === rule), `${file} debería activar ${rule}`);
        assert.notEqual(report.score.verdict, "clean");
    }
});

test("la entropía de datos uniformes es 0 y la de datos aleatorios cercana a 8", () => {
    assert.equal(shannonEntropy(Buffer.alloc(1024, 65)), 0);
    assert.ok(shannonEntropy(require("crypto").randomBytes(65536)) > 7.9);
});

test("extrae IOC e ignora dominios legítimos y números de versión", () => {
    const iocs = extractIndicators("http://malo.xyz/a.exe 45.33.12.9 version 6.1.0.0 https://www.microsoft.com HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x");
    const values = iocs.map((i) => `${i.type}:${i.value}`);
    assert.ok(values.includes("url:http://malo.xyz/a.exe"));
    assert.ok(values.includes("ipv4:45.33.12.9"));
    assert.ok(!values.some((v) => v.includes("microsoft.com")));
    assert.ok(!values.includes("ipv4:6.1.0.0"));
    assert.ok(values.some((v) => v.startsWith("registry:")));
});

test("lee las cabeceras PE de un ejecutable real (node.exe) sin falsos positivos", { skip: process.platform !== "win32" }, async () => {
    const pe = parsePE(fs.readFileSync(process.execPath));
    assert.ok(pe.valid);
    assert.equal(pe.architecture, "x64");
    assert.ok(pe.importCount > 50);

    const report = await analyze(fs.readFileSync(process.execPath), "node.exe");
    assert.equal(report.score.verdict, "clean");
});

test("el puntaje siempre explica sus razones", async () => {
    const report = await analyze(Buffer.from("MZ"), "a.pdf.exe");
    assert.ok(report.score.reasons.length > 0);
    for (const reason of report.score.reasons) {
        assert.ok(reason.label && reason.source);
    }
});
