/**
 * Identifica el tipo REAL de un archivo por sus bytes mágicos y lo compara
 * con la extensión declarada (detección de enmascaramiento, MITRE T1036).
 */

const EXTENSION_FAMILY = {
    executable: ["exe", "dll", "sys", "scr", "com", "cpl", "ocx", "drv", "efi", "msi", "so", "elf", "bin", "dylib", "pif"],
    script: ["ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "sh", "bash", "py", "pl", "rb", "php", "lnk"],
    document: ["pdf", "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "rtf", "odt", "ods"],
    archive: ["zip", "rar", "7z", "gz", "tgz", "tar", "iso", "img", "cab", "jar", "apk"],
    image: ["png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "svg"],
    text: ["txt", "log", "csv", "json", "xml", "md", "ini", "cfg", "conf", "yml", "yaml", "html", "htm", "css"]
};

const RISKY_FINAL_EXTENSIONS = ["exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "ps1", "hta", "wsf", "msi", "lnk", "cpl", "jar"];
const DECOY_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "mp3", "mp4", "zip", "rar"];

const startsWith = (buffer, bytes, offset = 0) =>
    buffer.length >= offset + bytes.length && bytes.every((b, i) => buffer[offset + i] === b);

const ascii = (buffer, start, end) => buffer.subarray(start, end).toString("latin1");

function familyOfExtension(ext) {
    return Object.keys(EXTENSION_FAMILY).find((family) => EXTENSION_FAMILY[family].includes(ext)) || "unknown";
}

function detectZipFlavor(buffer) {
    // Los nombres de archivo dentro del ZIP aparecen en texto plano en el directorio central
    const sample = buffer.length > 4 * 1024 * 1024
        ? ascii(buffer, 0, 1024 * 1024) + ascii(buffer, buffer.length - 1024 * 1024, buffer.length)
        : ascii(buffer, 0, buffer.length);
    const hasMacros = sample.includes("vbaProject.bin");

    if (sample.includes("[Content_Types].xml")) {
        if (sample.includes("word/")) return { type: "docx", label: "Documento Word (OOXML)", category: "document", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", hasMacros };
        if (sample.includes("xl/")) return { type: "xlsx", label: "Libro Excel (OOXML)", category: "document", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", hasMacros };
        if (sample.includes("ppt/")) return { type: "pptx", label: "Presentación PowerPoint (OOXML)", category: "document", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", hasMacros };
    }
    if (sample.includes("AndroidManifest.xml") && sample.includes("classes.dex")) return { type: "apk", label: "Aplicación Android (APK)", category: "executable", mime: "application/vnd.android.package-archive" };
    if (sample.includes("META-INF/MANIFEST.MF")) return { type: "jar", label: "Archivo Java (JAR)", category: "executable", mime: "application/java-archive" };
    return { type: "zip", label: "Archivo comprimido ZIP", category: "archive", mime: "application/zip", hasMacros };
}

function detectMagic(buffer) {
    if (startsWith(buffer, [0x4d, 0x5a])) return { type: "pe", label: "Ejecutable de Windows (PE)", category: "executable", mime: "application/vnd.microsoft.portable-executable" };
    if (startsWith(buffer, [0x7f, 0x45, 0x4c, 0x46])) return { type: "elf", label: "Ejecutable Linux (ELF)", category: "executable", mime: "application/x-executable" };
    if ([[0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], [0xcf, 0xfa, 0xed, 0xfe], [0xce, 0xfa, 0xed, 0xfe]].some((m) => startsWith(buffer, m))) {
        return { type: "macho", label: "Ejecutable macOS (Mach-O)", category: "executable", mime: "application/x-mach-binary" };
    }
    if (startsWith(buffer, [0x25, 0x50, 0x44, 0x46])) return { type: "pdf", label: "Documento PDF", category: "document", mime: "application/pdf" };
    if (startsWith(buffer, [0x50, 0x4b, 0x03, 0x04])) return detectZipFlavor(buffer);
    if (startsWith(buffer, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) {
        const text = ascii(buffer, 0, Math.min(buffer.length, 4 * 1024 * 1024));
        const hasMacros = /_VBA_PROJECT|VBA\x00|Macros/.test(text);
        const isMsi = text.includes("MsiDigitalSignature") || text.includes("Installer");
        return isMsi
            ? { type: "msi", label: "Instalador de Windows (MSI)", category: "executable", mime: "application/x-msi" }
            : { type: "ole", label: "Documento Office antiguo (OLE)", category: "document", mime: "application/x-ole-storage", hasMacros };
    }
    if (ascii(buffer, 0, 5) === "{\\rtf") return { type: "rtf", label: "Documento RTF", category: "document", mime: "application/rtf" };
    if (startsWith(buffer, [0x52, 0x61, 0x72, 0x21])) return { type: "rar", label: "Archivo comprimido RAR", category: "archive", mime: "application/vnd.rar" };
    if (startsWith(buffer, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { type: "7z", label: "Archivo comprimido 7-Zip", category: "archive", mime: "application/x-7z-compressed" };
    if (startsWith(buffer, [0x1f, 0x8b])) return { type: "gzip", label: "Archivo comprimido GZIP", category: "archive", mime: "application/gzip" };
    if (ascii(buffer, 0x8001, 0x8006) === "CD001") return { type: "iso", label: "Imagen de disco ISO", category: "archive", mime: "application/x-iso9660-image" };
    if (startsWith(buffer, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return { type: "lnk", label: "Acceso directo de Windows (LNK)", category: "script", mime: "application/x-ms-shortcut" };
    if (startsWith(buffer, [0x89, 0x50, 0x4e, 0x47])) return { type: "png", label: "Imagen PNG", category: "image", mime: "image/png" };
    if (startsWith(buffer, [0xff, 0xd8, 0xff])) return { type: "jpeg", label: "Imagen JPEG", category: "image", mime: "image/jpeg" };
    if (ascii(buffer, 0, 4) === "GIF8") return { type: "gif", label: "Imagen GIF", category: "image", mime: "image/gif" };
    if (ascii(buffer, 0, 4) === "RIFF" && ascii(buffer, 8, 12) === "WEBP") return { type: "webp", label: "Imagen WEBP", category: "image", mime: "image/webp" };
    if (ascii(buffer, 0, 2) === "BM" && buffer.length > 26) return { type: "bmp", label: "Imagen BMP", category: "image", mime: "image/bmp" };
    return null;
}

function looksLikeText(buffer) {
    const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
    if (sample.length === 0) return true;
    let printable = 0;
    for (const byte of sample) {
        if (byte === 0) return false;
        if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127) || byte >= 128) printable++;
    }
    return printable / sample.length > 0.95;
}

function detectTextFlavor(buffer, ext) {
    const head = buffer.subarray(0, 4096).toString("utf8");
    const scriptByExt = {
        ps1: "Script de PowerShell", psm1: "Módulo de PowerShell", vbs: "Script VBScript", vbe: "Script VBScript codificado",
        js: "Script JavaScript", jse: "Script JScript codificado", wsf: "Windows Script File", hta: "Aplicación HTML (HTA)",
        bat: "Script por lotes (BAT)", cmd: "Script por lotes (CMD)", sh: "Script de shell", bash: "Script de shell",
        py: "Script de Python", pl: "Script de Perl", php: "Script PHP", rb: "Script de Ruby"
    };

    if (scriptByExt[ext]) return { type: ext, label: scriptByExt[ext], category: "script", mime: "text/plain" };
    if (head.startsWith("#!")) return { type: "shebang", label: "Script ejecutable (shebang)", category: "script", mime: "text/x-shellscript" };
    if (/<\s*(html|script|!doctype)/i.test(head)) return { type: "html", label: "Documento HTML", category: "text", mime: "text/html" };
    if (/^\s*[{[]/.test(head)) return { type: "json", label: "Datos JSON", category: "text", mime: "application/json" };
    if (/^\s*<\?xml/.test(head)) return { type: "xml", label: "Documento XML", category: "text", mime: "application/xml" };
    return { type: "text", label: "Texto plano", category: "text", mime: "text/plain" };
}

function detectFileType(buffer, originalName = "") {
    const cleanName = originalName.replace(/[‪-‮⁦-⁩]/g, "");
    const parts = cleanName.toLowerCase().split(".");
    const extension = parts.length > 1 ? parts.pop() : "";
    const previousExtension = parts.length > 1 ? parts[parts.length - 1] : "";

    const detected = detectMagic(buffer)
        || (looksLikeText(buffer) ? detectTextFlavor(buffer, extension) : { type: "binary", label: "Datos binarios", category: "binary", mime: "application/octet-stream" });

    const declaredFamily = familyOfExtension(extension);
    const isExecutable = detected.category === "executable";

    let mismatch = null;
    if (isExecutable && !["executable", "archive"].includes(declaredFamily) && !(detected.type === "apk" && extension === "apk")) {
        mismatch = { severity: "critical", message: `Es un ${detected.label.toLowerCase()} disfrazado con extensión .${extension || "(ninguna)"}` };
    } else if (declaredFamily !== "unknown" && declaredFamily !== detected.category &&
        !(declaredFamily === "archive" && ["document", "executable"].includes(detected.category)) &&
        !(declaredFamily === "text" && ["text", "script"].includes(detected.category)) &&
        !(declaredFamily === "script" && detected.category === "text")) {
        mismatch = { severity: "medium", message: `La extensión .${extension} no corresponde al contenido real (${detected.label})` };
    }

    const doubleExtension = Boolean(
        previousExtension && DECOY_EXTENSIONS.includes(previousExtension) && RISKY_FINAL_EXTENSIONS.includes(extension)
    );
    const rtlo = cleanName !== originalName;

    return {
        ...detected,
        hasMacros: Boolean(detected.hasMacros),
        extension,
        declaredFamily,
        mismatch,
        doubleExtension: doubleExtension || rtlo,
        rtlo
    };
}

module.exports = { detectFileType, looksLikeText };
