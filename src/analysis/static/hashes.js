const crypto = require("crypto");

const digest = (algorithm, buffer) => crypto.createHash(algorithm).update(buffer).digest("hex");

function computeHashes(buffer) {
    return {
        md5: digest("md5", buffer),
        sha1: digest("sha1", buffer),
        sha256: digest("sha256", buffer)
    };
}

module.exports = { computeHashes };
