const RULES = require("./definitions");

const MAX_EVIDENCE = 5;

function describePattern(pattern) {
    return pattern instanceof RegExp ? pattern.source : pattern;
}

/** Busca el patrón y devuelve un fragmento del texto como evidencia */
function findPattern(haystack, lowerHaystack, pattern) {
    if (pattern instanceof RegExp) {
        const regex = new RegExp(pattern.source, pattern.flags.replace("g", ""));
        const match = regex.exec(haystack);
        return match ? snippet(haystack, match.index, match[0].length) : null;
    }
    const index = lowerHaystack.indexOf(pattern.toLowerCase());
    return index === -1 ? null : snippet(haystack, index, pattern.length);
}

function snippet(text, index, length) {
    const start = Math.max(0, index - 20);
    const end = Math.min(text.length, index + Math.max(length, 1) + 20);
    return text.slice(start, end).replace(/[^\x20-\x7e]+/g, " ").trim().slice(0, 120);
}

/**
 * Ejecuta todas las reglas.
 * @param {{ haystack: string, fileInfo: object }} ctx
 */
function runRules(ctx) {
    const lowerHaystack = ctx.haystack.toLowerCase();
    const matches = [];

    for (const rule of RULES) {
        if (rule.targets && !rule.targets.includes(ctx.fileInfo.category)) continue;
        if (rule.when && !rule.when(ctx)) continue;

        const evidence = [];
        for (const pattern of rule.patterns) {
            const found = findPattern(ctx.haystack, lowerHaystack, pattern);
            if (found) evidence.push({ pattern: describePattern(pattern), match: found });
        }

        const required = rule.patterns.length === 0 ? 0 : (rule.min || 1);
        if (evidence.length < required) continue;

        matches.push({
            ruleId: rule.id,
            name: rule.name,
            description: rule.description,
            severity: rule.severity,
            category: rule.category,
            family: rule.family || null,
            techniques: rule.techniques,
            evidence: evidence.slice(0, MAX_EVIDENCE)
        });
    }

    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return matches.sort((a, b) => order[a.severity] - order[b.severity]);
}

module.exports = { runRules, RULES };
