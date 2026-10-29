const virustotal = require("./virustotal");
const malwarebazaar = require("./malwarebazaar");
const circl = require("./circl");
const urlhaus = require("./urlhaus");

/** Proveedores de inteligencia de amenazas, en el orden en que se muestran */
const PROVIDERS = [virustotal, malwarebazaar, circl, urlhaus];

/** Motores locales de SACM (siempre activos) */
const LOCAL_ENGINES = [
    { id: "sacm_static", name: "Análisis estático SACM", description: "Tipo real del archivo, entropía, cabeceras PE e indicadores" },
    { id: "sacm_rules", name: "Reglas SACM + MITRE ATT&CK", description: "Reglas de comportamiento mapeadas a técnicas de ATT&CK" }
];

const getProvider = (id) => PROVIDERS.find((p) => p.id === id);

function describeIntegrations() {
    return [
        ...LOCAL_ENGINES.map((e) => ({ ...e, type: "local", enabled: true, requiresKey: null, url: null })),
        ...PROVIDERS.map((p) => ({
            id: p.id,
            name: p.name,
            description: p.description,
            type: "external",
            url: p.url,
            requiresKey: p.requiresKey,
            enabled: p.isEnabled()
        }))
    ];
}

module.exports = { PROVIDERS, LOCAL_ENGINES, getProvider, describeIntegrations };
