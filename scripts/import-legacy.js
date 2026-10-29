/**
 * Importa los usuarios de la versión 1 de SACM (base LEGACY_DB_NAME).
 * Conserva nombre, correo, rol y el hash bcrypt, así que las contraseñas siguen sirviendo.
 */
const crypto = require("crypto");
const mysql = require("mysql2/promise");
const env = require("../src/config/env");
const db = require("../src/config/database");
const { ROLE_IDS } = require("../src/utils/roles");

async function main() {
    const legacy = await mysql.createConnection({
        host: env.DB_HOST,
        port: env.DB_PORT,
        user: env.DB_USER,
        password: env.DB_PASSWORD,
        database: env.LEGACY_DB_NAME
    });

    const [users] = await legacy.query(
        `SELECT u.fullname, u.email, u.password, u.created_at, r.role_name, p.department
         FROM users u INNER JOIN roles r ON r.id = u.role_id
         LEFT JOIN user_profiles p ON p.user_id = u.id`
    );
    await legacy.end();

    let imported = 0;
    for (const user of users) {
        const email = String(user.email).trim().toLowerCase();
        if (await db.queryOne("SELECT id FROM users WHERE email = ?", [email])) {
            console.log(`  · ${email} ya existe, se omite`);
            continue;
        }
        const id = crypto.randomUUID();
        await db.transaction(async (tx) => {
            await tx.query(
                "INSERT INTO users (id, role_id, full_name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [id, ROLE_IDS[user.role_name] || ROLE_IDS.USER, user.fullname, email, user.password, user.created_at || new Date()]
            );
            await tx.query("INSERT INTO user_profiles (user_id, department) VALUES (?, ?)", [id, user.department || null]);
        });
        console.log(`  + ${email} (${user.role_name})`);
        imported++;
    }

    console.log(`✅ ${imported} usuario(s) importados desde "${env.LEGACY_DB_NAME}"`);
    await db.pool.end();
}

main().catch(async (error) => {
    console.error("❌ No se pudo importar:", error.message);
    await db.pool.end();
    process.exit(1);
});
