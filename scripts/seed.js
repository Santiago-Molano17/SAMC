/**
 * Crea las cuentas de demostración.
 *   npm run db:seed            → solo usuarios demo
 *   npm run db:seed -- --demo  → usuarios + análisis, casos y revisiones de ejemplo
 */
const db = require("../src/config/database");
const { createUser } = require("../src/modules/auth/auth.service");
const { ROLE_IDS } = require("../src/utils/roles");

const DEMO_PASSWORD = "Sacm2026!";

const DEMO_USERS = [
    { fullName: "Valentina Ríos", email: "superadmin@sacm.local", role: "SUPER_ADMIN", jobTitle: "CISO", department: "Seguridad de la información" },
    { fullName: "Andrés Gómez", email: "admin@sacm.local", role: "ADMIN", jobTitle: "Administrador de plataforma", department: "Tecnología" },
    { fullName: "Laura Martínez", email: "analista@sacm.local", role: "ANALYST", jobTitle: "Analista SOC N2", department: "Centro de Operaciones de Seguridad" },
    { fullName: "Carlos Pérez", email: "analista2@sacm.local", role: "ANALYST", jobTitle: "Threat Hunter", department: "Centro de Operaciones de Seguridad" },
    { fullName: "María Fernández", email: "usuario@sacm.local", role: "USER", jobTitle: "Contadora", department: "Finanzas" },
    { fullName: "Juan Torres", email: "usuario2@sacm.local", role: "USER", jobTitle: "Ejecutivo comercial", department: "Ventas" }
];

async function seedUsers() {
    const ids = {};
    for (const user of DEMO_USERS) {
        const existing = await db.queryOne("SELECT id FROM users WHERE email = ?", [user.email]);
        if (existing) {
            ids[user.email] = existing.id;
            console.log(`  · ${user.email} ya existe`);
            continue;
        }
        ids[user.email] = await createUser({
            fullName: user.fullName,
            email: user.email,
            password: DEMO_PASSWORD,
            roleId: ROLE_IDS[user.role],
            profile: { jobTitle: user.jobTitle, department: user.department }
        });
        console.log(`  + ${user.email} (${user.role})`);
    }
    return ids;
}

async function main() {
    console.log("👤 Usuarios de demostración");
    const ids = await seedUsers();

    if (process.argv.includes("--demo")) {
        console.log("\n🧪 Datos de demostración");
        await require("./demo-data").generate(ids);
    }

    console.log(`\n✅ Listo. Contraseña de las cuentas demo: ${DEMO_PASSWORD}`);
    await db.pool.end();
}

main().catch(async (error) => {
    console.error("❌ Error en el seed:", error.message);
    await db.pool.end();
    process.exit(1);
});
