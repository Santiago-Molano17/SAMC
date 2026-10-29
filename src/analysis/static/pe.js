/**
 * Lector mínimo de ejecutables PE (Windows): cabeceras, secciones e importaciones.
 * Nunca ejecuta el archivo; solo lee estructuras con validación de límites.
 */
const { shannonEntropy, round } = require("./entropy");

const MACHINES = { 0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64", 0x1c0: "ARM", 0x1c4: "ARMv7" };
const SUBSYSTEMS = { 1: "Nativo", 2: "Interfaz gráfica (GUI)", 3: "Consola", 9: "Windows CE", 10: "Aplicación EFI", 16: "Boot de Windows" };
const PACKER_SECTIONS = {
    UPX0: "UPX", UPX1: "UPX", UPX2: "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".petite": "Petite", MPRESS1: "MPRESS", MPRESS2: "MPRESS",
    ".nsp0": "NsPack", ".enigma1": "Enigma", ".packed": "Genérico", ".mpress": "MPRESS"
};

const SCN_EXECUTE = 0x20000000;
const SCN_READ = 0x40000000;
const SCN_WRITE = 0x80000000;

function readCString(buffer, offset, max = 256) {
    if (offset < 0 || offset >= buffer.length) return null;
    const end = buffer.indexOf(0, offset);
    const stop = end === -1 ? Math.min(buffer.length, offset + max) : Math.min(end, offset + max);
    return buffer.subarray(offset, stop).toString("latin1");
}

function parsePE(buffer) {
    if (buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) return null;

    try {
        const peOffset = buffer.readUInt32LE(0x3c);
        if (peOffset + 24 > buffer.length || buffer.readUInt32LE(peOffset) !== 0x00004550) {
            return { valid: false, reason: "Cabecera MZ sin firma PE válida" };
        }

        const coff = peOffset + 4;
        const machine = buffer.readUInt16LE(coff);
        const numberOfSections = Math.min(buffer.readUInt16LE(coff + 2), 96);
        const timestamp = buffer.readUInt32LE(coff + 4);
        const sizeOfOptionalHeader = buffer.readUInt16LE(coff + 16);
        const characteristics = buffer.readUInt16LE(coff + 18);

        const opt = coff + 20;
        const magic = buffer.readUInt16LE(opt);
        const is64 = magic === 0x20b;
        const entryPoint = buffer.readUInt32LE(opt + 16);
        const subsystem = buffer.readUInt16LE(opt + 68);
        const dataDirOffset = opt + (is64 ? 112 : 96);

        const sections = [];
        const sectionTable = opt + sizeOfOptionalHeader;
        for (let i = 0; i < numberOfSections; i++) {
            const s = sectionTable + i * 40;
            if (s + 40 > buffer.length) break;
            const rawSize = buffer.readUInt32LE(s + 16);
            const rawPointer = buffer.readUInt32LE(s + 20);
            const flags = buffer.readUInt32LE(s + 36);
            const name = buffer.subarray(s, s + 8).toString("latin1").replace(/\0+$/, "");
            const end = Math.min(buffer.length, rawPointer + rawSize);

            sections.push({
                name,
                virtualAddress: buffer.readUInt32LE(s + 12),
                virtualSize: buffer.readUInt32LE(s + 8),
                rawSize,
                rawPointer,
                entropy: rawPointer < buffer.length && end > rawPointer ? round(shannonEntropy(buffer, rawPointer, end)) : 0,
                readable: Boolean(flags & SCN_READ),
                writable: Boolean(flags & SCN_WRITE),
                executable: Boolean(flags & SCN_EXECUTE),
                packer: PACKER_SECTIONS[name] || null
            });
        }

        const rvaToOffset = (rva) => {
            const section = sections.find((sec) => rva >= sec.virtualAddress && rva < sec.virtualAddress + Math.max(sec.virtualSize, sec.rawSize));
            return section ? rva - section.virtualAddress + section.rawPointer : -1;
        };

        const imports = parseImports(buffer, dataDirOffset, is64, rvaToOffset);
        const entrySection = sections.find((sec) => entryPoint >= sec.virtualAddress && entryPoint < sec.virtualAddress + Math.max(sec.virtualSize, sec.rawSize));
        const lastSectionEnd = sections.reduce((max, sec) => Math.max(max, sec.rawPointer + sec.rawSize), 0);
        const compiledAt = timestamp ? new Date(timestamp * 1000) : null;

        return {
            valid: true,
            architecture: MACHINES[machine] || `0x${machine.toString(16)}`,
            format: is64 ? "PE32+" : "PE32",
            isDll: Boolean(characteristics & 0x2000),
            subsystem: SUBSYSTEMS[subsystem] || `Desconocido (${subsystem})`,
            compiledAt: compiledAt ? compiledAt.toISOString() : null,
            futureTimestamp: Boolean(compiledAt && compiledAt.getTime() > Date.now() + 86400000),
            entryPoint: `0x${entryPoint.toString(16)}`,
            entrySection: entrySection?.name || null,
            sections,
            imports,
            importCount: imports.reduce((n, lib) => n + lib.functions.length, 0),
            overlaySize: lastSectionEnd > 0 && buffer.length > lastSectionEnd ? buffer.length - lastSectionEnd : 0,
            packers: [...new Set(sections.map((sec) => sec.packer).filter(Boolean))]
        };
    } catch (error) {
        return { valid: false, reason: `PE malformado: ${error.message}` };
    }
}

function parseImports(buffer, dataDirOffset, is64, rvaToOffset) {
    const imports = [];
    if (dataDirOffset + 16 > buffer.length) return imports;

    const importRva = buffer.readUInt32LE(dataDirOffset + 8);
    if (!importRva) return imports;

    let descriptor = rvaToOffset(importRva);
    for (let d = 0; descriptor > 0 && descriptor + 20 <= buffer.length && d < 64; d++, descriptor += 20) {
        const originalThunk = buffer.readUInt32LE(descriptor);
        const nameRva = buffer.readUInt32LE(descriptor + 12);
        const firstThunk = buffer.readUInt32LE(descriptor + 16);
        if (!nameRva && !firstThunk) break;

        const library = readCString(buffer, rvaToOffset(nameRva), 128);
        if (!library) break;

        const functions = [];
        let thunk = rvaToOffset(originalThunk || firstThunk);
        const step = is64 ? 8 : 4;
        for (let f = 0; thunk > 0 && thunk + step <= buffer.length && f < 400; f++, thunk += step) {
            const value = is64 ? Number(buffer.readBigUInt64LE(thunk) & 0x7fffffffn) : buffer.readUInt32LE(thunk);
            const isOrdinal = is64 ? (buffer.readBigUInt64LE(thunk) >> 63n) === 1n : (value & 0x80000000) !== 0;
            if (!value && !isOrdinal) break;
            if (isOrdinal) {
                functions.push(`#${value & 0xffff}`);
                continue;
            }
            const name = readCString(buffer, rvaToOffset(value) + 2, 128);
            if (name) functions.push(name);
        }

        imports.push({ library: library.toLowerCase(), functions });
    }
    return imports;
}

module.exports = { parsePE };
