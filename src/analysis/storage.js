/**
 * Almacén de muestras "neutralizadas": cada archivo se guarda con XOR para que
 * no pueda ejecutarse por accidente ni lo borre el antivirus del servidor
 * (la misma idea que el ZIP con contraseña "infected" de los laboratorios).
 */
const fs = require("fs/promises");
const path = require("path");
const env = require("../config/env");

const SAMPLES_DIR = path.join(env.storageDir, "samples");
const KEY = Buffer.from("SACM-quarantine-v2");

function xor(buffer) {
    const out = Buffer.allocUnsafe(buffer.length);
    for (let i = 0; i < buffer.length; i++) out[i] = buffer[i] ^ KEY[i % KEY.length];
    return out;
}

const samplePath = (sha256) => path.join(SAMPLES_DIR, `${sha256.replace(/[^a-f0-9]/g, "")}.quarantine`);

async function saveSample(sha256, buffer) {
    await fs.mkdir(SAMPLES_DIR, { recursive: true });
    const target = samplePath(sha256);
    try {
        await fs.access(target);
    } catch {
        await fs.writeFile(target, xor(buffer));
    }
}

async function readSample(sha256) {
    try {
        return xor(await fs.readFile(samplePath(sha256)));
    } catch {
        return null;
    }
}

module.exports = { saveSample, readSample };
