/**
 * Aplica las migraciones pendientes de database/migrations en orden.
 * Cada migración se registra en schema_migrations para no repetirla.
 */
const fs = require("fs");
const path = require("path");
const mysql = require("mysql2/promise");
const env = require("../src/config/env");

const MIGRATIONS_DIR = path.join(__dirname, "..", "database", "migrations");

async function main() {
    const connection = await mysql.createConnection({
        host: env.DB_HOST,
        port: env.DB_PORT,
        user: env.DB_USER,
        password: env.DB_PASSWORD,
        multipleStatements: true
    });

    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${env.DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    await connection.query(`USE \`${env.DB_NAME}\``);
    await connection.query("SET time_zone = '+00:00'");
    await connection.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    VARCHAR(100) PRIMARY KEY,
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB`);

    const [rows] = await connection.query("SELECT version FROM schema_migrations");
    const applied = new Set(rows.map((r) => r.version));
    const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();

    let count = 0;
    for (const file of files) {
        if (applied.has(file)) continue;
        process.stdout.write(`→ Aplicando ${file}... `);
        await connection.query(fs.readFileSync(path.join(MIGRATIONS_DIR, file), "utf8"));
        await connection.query("INSERT INTO schema_migrations (version) VALUES (?)", [file]);
        console.log("ok");
        count++;
    }

    console.log(count ? `✅ ${count} migración(es) aplicadas en "${env.DB_NAME}"` : `✅ "${env.DB_NAME}" ya está al día`);
    await connection.end();
}

main().catch((error) => {
    console.error("\n❌ Error en la migración:", error.message);
    process.exit(1);
});
