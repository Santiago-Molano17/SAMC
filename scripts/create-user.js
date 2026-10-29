/**
 * Crea un usuario desde la terminal.
 * Uso: npm run user:create -- "Nombre Completo" correo@ejemplo.com "Contrasena123" SUPER_ADMIN
 */
const db = require("../src/config/database");
const { createUser } = require("../src/modules/auth/auth.service");
const { password: passwordSchema } = require("../src/modules/auth/auth.schemas");
const { ROLE_IDS } = require("../src/utils/roles");

async function main() {
    const [fullName, email, password, role = "USER"] = process.argv.slice(2);
    if (!fullName || !email || !password || !ROLE_IDS[role]) {
        console.log('Uso: npm run user:create -- "Nombre Completo" correo@ejemplo.com "Contrasena123" [SUPER_ADMIN|ADMIN|ANALYST|USER]');
        process.exit(1);
    }
    const check = passwordSchema.safeParse(password);
    if (!check.success) {
        console.log(`❌ Contraseña inválida: ${check.error.issues[0].message}`);
        process.exit(1);
    }
    await createUser({ fullName, email: email.toLowerCase(), password, roleId: ROLE_IDS[role] });
    console.log(`✅ Usuario ${email.toLowerCase()} creado con rol ${role}`);
}

main()
    .catch((error) => {
        console.error("❌", error.message);
        process.exitCode = 1;
    })
    .finally(() => db.pool.end());
