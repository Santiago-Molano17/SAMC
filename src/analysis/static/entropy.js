/**
 * Entropía de Shannon en bits por byte (0 a 8).
 * Valores cercanos a 8 indican datos comprimidos o cifrados (posible empaquetado).
 */
function shannonEntropy(buffer, start = 0, end = buffer.length) {
    const length = end - start;
    if (length <= 0) return 0;

    const counts = new Uint32Array(256);
    for (let i = start; i < end; i++) counts[buffer[i]]++;

    let entropy = 0;
    for (const count of counts) {
        if (count === 0) continue;
        const p = count / length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/** Perfil de entropía por bloques, para graficar dónde está el contenido cifrado */
function entropyProfile(buffer, blocks = 64) {
    if (buffer.length === 0) return [];
    const blockSize = Math.max(256, Math.ceil(buffer.length / blocks));
    const profile = [];
    for (let start = 0; start < buffer.length; start += blockSize) {
        profile.push(round(shannonEntropy(buffer, start, Math.min(buffer.length, start + blockSize))));
    }
    return profile;
}

const round = (value) => Math.round(value * 1000) / 1000;

module.exports = { shannonEntropy, entropyProfile, round };
