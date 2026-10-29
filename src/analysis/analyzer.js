/**
 * Análisis completo de un archivo, sin depender de la base de datos.
 * Lo usan el pipeline del servidor, los scripts y las pruebas.
 */
const { computeHashes } = require("./static/hashes");
const { shannonEntropy, entropyProfile, round } = require("./static/entropy");
const { detectFileType } = require("./static/filetype");
const { extractStrings, extractIndicators, pickStringSample } = require("./static/strings");
const { parsePE } = require("./static/pe");
const { runRules } = require("./rules/engine");
const { computeScore } = require("./scoring");
const { PROVIDERS } = require("./providers");

const HAYSTACK_LIMIT = 16 * 1024 * 1024;

async function timed(fn) {
    const started = Date.now();
    try {
        const result = await fn();
        return { ...result, durationMs: Date.now() - started };
    } catch (error) {
        return { status: "error", verdict: "unknown", summary: error.message, durationMs: Date.now() - started };
    }
}

function buildHaystack(buffer, fileInfo, strings, pe) {
    // Texto: se analiza completo. Binario: cadenas extraídas + importaciones del PE.
    const base = ["text", "script"].includes(fileInfo.category)
        ? buffer.subarray(0, HAYSTACK_LIMIT).toString("utf8")
        : buffer.subarray(0, HAYSTACK_LIMIT).toString("latin1");
    const extra = [strings.join("\n")];
    if (pe?.valid) extra.push(pe.imports.flatMap((lib) => [lib.library, ...lib.functions]).join("\n"));
    return `${base}\n${extra.join("\n")}`;
}

/**
 * @param {Buffer} buffer
 * @param {string} originalName
 * @param {{ providers?: Array, external?: boolean }} options
 */
async function analyzeBuffer(buffer, originalName, { providers, external = true } = {}) {
    const started = Date.now();
    const hashes = computeHashes(buffer);

    const fileInfo = detectFileType(buffer, originalName);
    const entropy = { overall: round(shannonEntropy(buffer)), profile: entropyProfile(buffer) };
    const pe = fileInfo.type === "pe" ? parsePE(buffer) : null;

    const strings = extractStrings(buffer);
    const iocText = strings.map((s) => s.slice(0, 1000)).join("\n");
    const indicators = extractIndicators(iocText, { allowLegacyBitcoin: ["text", "script"].includes(fileInfo.category) });

    const haystack = buildHaystack(buffer, fileInfo, strings, pe);
    const ruleMatches = runRules({ haystack, fileInfo });
    const staticMs = Date.now() - started;

    const sample = { ...hashes, size: buffer.length };
    const engines = {
        sacm_static: {
            status: "ok",
            verdict: fileInfo.mismatch?.severity === "critical" || fileInfo.doubleExtension ? "malicious" : fileInfo.mismatch ? "suspicious" : "clean",
            summary: `${fileInfo.label} · entropía ${entropy.overall} · ${indicators.length} indicadores`,
            details: { type: fileInfo.type, mismatch: fileInfo.mismatch, doubleExtension: fileInfo.doubleExtension, packers: pe?.packers || [] },
            durationMs: staticMs
        },
        sacm_rules: {
            status: "ok",
            verdict: ruleMatches.some((r) => ["critical", "high"].includes(r.severity)) ? "malicious" : ruleMatches.length ? "suspicious" : "clean",
            detections: ruleMatches.length,
            summary: ruleMatches.length ? `${ruleMatches.length} regla(s) coinciden` : "Ninguna regla coincide",
            details: { techniques: [...new Set(ruleMatches.flatMap((r) => r.techniques))] },
            durationMs: staticMs
        }
    };

    if (external) {
        const enabled = (providers || PROVIDERS).filter((p) => p.isEnabled());
        const results = await Promise.all(enabled.map((p) => timed(() => p.lookup({ sample, buffer, indicators, fileInfo }))));
        enabled.forEach((p, i) => { engines[p.id] = results[i]; });
    }

    // Marca los IOC que URLhaus reportó como maliciosos
    const maliciousHosts = new Set(engines.urlhaus?.maliciousHosts || []);
    for (const ioc of indicators) {
        let host = ioc.value;
        if (ioc.type === "url") {
            try { host = new URL(ioc.value).hostname; } catch { host = ""; }
        }
        if (maliciousHosts.has(host)) {
            ioc.isMalicious = true;
            ioc.source = "urlhaus";
        }
    }

    const score = computeScore({ fileInfo, entropy, pe, ruleMatches, engines });

    return {
        hashes,
        size: buffer.length,
        fileInfo,
        entropy,
        pe,
        strings: { total: strings.length, sample: pickStringSample(strings) },
        indicators,
        ruleMatches,
        engines,
        score,
        durationMs: Date.now() - started
    };
}

module.exports = { analyzeBuffer };
