const path = require("path");
const { z } = require("zod");

require("dotenv").config({ path: path.join(__dirname, "..", "..", ".env"), quiet: true });

const bool = (fallback) => z
    .enum(["true", "false"])
    .default(fallback ? "true" : "false")
    .transform((value) => value === "true");

const schema = z.object({
    NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
    PORT: z.coerce.number().int().positive().default(5000),

    DB_HOST: z.string().default("localhost"),
    DB_PORT: z.coerce.number().int().positive().default(3306),
    DB_USER: z.string().min(1),
    DB_PASSWORD: z.string().default(""),
    DB_NAME: z.string().regex(/^[a-zA-Z0-9_]+$/, "Solo letras, números y guion bajo").default("sacm_v2"),
    LEGACY_DB_NAME: z.string().regex(/^[a-zA-Z0-9_]+$/).default("sacm"),

    JWT_SECRET: z.string().min(32, "JWT_SECRET debe tener al menos 32 caracteres"),
    JWT_EXPIRES_IN: z.string().default("8h"),
    MAX_UPLOAD_MB: z.coerce.number().positive().max(200).default(32),

    VIRUSTOTAL_API_KEY: z.string().default(""),
    VIRUSTOTAL_UPLOAD_UNKNOWN: bool(false),
    ABUSECH_AUTH_KEY: z.string().default(""),
    CIRCL_HASHLOOKUP_ENABLED: bool(true),
    ANALYSIS_CONCURRENCY: z.coerce.number().int().min(1).max(8).default(2)
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
    console.error("❌ Configuración inválida en .env:");
    for (const issue of parsed.error.issues) {
        console.error(`   - ${issue.path.join(".")}: ${issue.message}`);
    }
    process.exit(1);
}

const env = parsed.data;

module.exports = {
    ...env,
    isProduction: env.NODE_ENV === "production",
    rootDir: path.join(__dirname, "..", ".."),
    storageDir: path.join(__dirname, "..", "..", "storage")
};
