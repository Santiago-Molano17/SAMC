/**
 * Extracción de cadenas legibles (ASCII y UTF-16LE) e indicadores de compromiso (IOC).
 */

const MAX_STRINGS = 20000;
const MAX_PER_IOC_TYPE = 50;

// Dominios frecuentes en archivos legítimos que solo generan ruido
const BENIGN_DOMAINS = [
    "microsoft.com", "windows.com", "w3.org", "openxmlformats.org", "adobe.com", "verisign.com",
    "digicert.com", "globalsign.com", "sectigo.com", "symantec.com", "thawte.com", "apache.org",
    "mozilla.org", "purl.org", "xmlsoap.org", "schemas.android.com", "google.com", "apple.com",
    "example.com", "localhost.localdomain", "chromium.org", "python.org", "github.com"
];

const TLDS = "com|net|org|info|biz|io|co|ru|cn|su|top|xyz|online|site|club|shop|live|icu|cc|tk|ml|ga|cf|gq|pw|ws|me|us|uk|de|fr|br|in|es|mx|ar|cl|pe|ve|ir|kp|onion|bit|app|dev|cloud|link|click|space|tech|store|win|bid|loan|work";

const PATTERNS = {
    url: /\bh(?:tt|xx)ps?:\/\/[^\s"'<>\\^`{|}\x00]{4,300}/gi,
    domain: new RegExp(`\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${TLDS})\\b`, "gi"),
    ipv4: /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g,
    email: /\b[a-z0-9._%+-]{2,64}@[a-z0-9.-]+\.[a-z]{2,10}\b/gi,
    registry: /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)\\[\w\\ .{}()-]{3,200}/gi,
    path: /(?:\b[a-zA-Z]:\\|%(?:APPDATA|TEMP|TMP|USERPROFILE|PROGRAMDATA|LOCALAPPDATA|WINDIR|SYSTEMROOT)%\\)(?:[^\\/:*?"<>|\r\n\x00]{1,80}\\){0,8}[^\\/:*?"<>|\r\n\x00 ]{1,80}/gi,
    bitcoin: /\bbc1[a-z0-9]{25,39}\b/g
};

function extractStrings(buffer, minLength = 5) {
    const results = new Set();

    // ASCII imprimible
    let current = "";
    for (let i = 0; i < buffer.length && results.size < MAX_STRINGS; i++) {
        const byte = buffer[i];
        if (byte >= 0x20 && byte < 0x7f) {
            current += String.fromCharCode(byte);
        } else {
            if (current.length >= minLength) results.add(current);
            current = "";
        }
    }
    if (current.length >= minLength) results.add(current);

    // UTF-16LE (muy común en binarios de Windows)
    current = "";
    for (let i = 0; i + 1 < buffer.length && results.size < MAX_STRINGS; i += 2) {
        const low = buffer[i];
        const high = buffer[i + 1];
        if (high === 0 && low >= 0x20 && low < 0x7f) {
            current += String.fromCharCode(low);
        } else {
            if (current.length >= minLength) results.add(current);
            current = "";
        }
    }
    if (current.length >= minLength) results.add(current);

    return [...results];
}

const isBenignDomain = (domain) =>
    BENIGN_DOMAINS.some((benign) => domain === benign || domain.endsWith(`.${benign}`));

function normalizeUrl(url) {
    return url.replace(/^hxxp/i, "http").replace(/[),.;]+$/, "");
}

function extractIndicators(text, { allowLegacyBitcoin = false } = {}) {
    const found = { url: new Set(), domain: new Set(), ipv4: new Set(), email: new Set(), registry: new Set(), path: new Set(), bitcoin: new Set() };
    const add = (type, value) => {
        if (found[type].size < MAX_PER_IOC_TYPE) found[type].add(value.slice(0, 500));
    };

    for (const match of text.matchAll(PATTERNS.url)) {
        const url = normalizeUrl(match[0]);
        try {
            const host = new URL(url).hostname.toLowerCase();
            if (isBenignDomain(host)) continue;
            add("url", url);
        } catch {
            // URL malformada: se ignora
        }
    }

    for (const match of text.matchAll(PATTERNS.domain)) {
        const domain = match[0].toLowerCase();
        // Evita confundir nombres de archivo (ej: "kernel32.dll" no aplica, pero "setup.exe.com" sí)
        if (isBenignDomain(domain) || /^\d+\./.test(domain)) continue;
        add("domain", domain);
    }

    for (const match of text.matchAll(PATTERNS.ipv4)) {
        const ip = match[0];
        const octets = ip.split(".").map(Number);
        const versionLike = octets.every((o) => o < 10);
        if (versionLike || octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 || ip === "255.255.255.255") continue;
        add("ipv4", ip);
    }

    for (const match of text.matchAll(PATTERNS.email)) {
        const email = match[0].toLowerCase();
        if (!isBenignDomain(email.split("@")[1])) add("email", email);
    }

    for (const match of text.matchAll(PATTERNS.registry)) add("registry", match[0].trim());
    for (const match of text.matchAll(PATTERNS.path)) add("path", match[0].trim());
    for (const match of text.matchAll(PATTERNS.bitcoin)) add("bitcoin", match[0]);

    if (allowLegacyBitcoin && /bitcoin|btc|wallet|monedero/i.test(text)) {
        for (const match of text.matchAll(/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g)) add("bitcoin", match[0]);
    }

    // Los dominios que ya aparecen dentro de una URL no se duplican
    const urlHosts = new Set([...found.url].map((u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } }));
    for (const domain of found.domain) if (urlHosts.has(domain)) found.domain.delete(domain);

    return Object.entries(found).flatMap(([type, values]) => [...values].map((value) => ({ type, value })));
}

const INTERESTING = /https?:|\\|\.exe|\.dll|\.ps1|cmd|powershell|http|reg|run|key|pass|token|crypt|shell|exec|alloc|thread|hook|inject|download|socket|connect|admin|bitcoin|wallet|ransom|vssadmin|schtasks/i;

/** Muestra de cadenas para el reporte: primero las relevantes */
function pickStringSample(strings, limit = 150) {
    const interesting = [];
    const rest = [];
    for (const s of strings) {
        if (s.length > 200) continue;
        (INTERESTING.test(s) ? interesting : rest).push(s);
    }
    return [...interesting.slice(0, limit), ...rest].slice(0, limit);
}

module.exports = { extractStrings, extractIndicators, pickStringSample };
