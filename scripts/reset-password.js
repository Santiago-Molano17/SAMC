/**
 * Cambia la contraseña de una cuenta y desbloquea la cuenta.
 * Uso: npm run user:reset-password -- correo@ejemplo.com "NuevaClave123"
 */
const db = require("../src/config/database");
const { hashPassword } = require("../src/modules/auth/auth.service");
const { password: passwordSchema } = require("../src/modules/auth/auth.schemas");

async function main() {
    const [email, password] = process.argv.slice(2);
    if (!email || !password) {
        console.log('Uso: npm run user:reset-password -- correo@ejemplo.com "NuevaClave123"');
        process.exit(1);
    }
    const check = passwordSchema.safeParse(password);
    if (!check.success) {
        console.log(`❌ Contraseña inválida: ${check.error.issues[0].message}`);
        process.exit(1);
    }
    const result = await db.query(
        `UPDATE users SET password_hash = ?, password_changed_at = UTC_TIMESTAMP(), failed_login_attempts = 0, locked_until = NULL
         WHERE email = ?`,
        [await hashPassword(password), email.toLowerCase()]
    );
    console.log(result.affectedRows ? `✅ Contraseña actualizada para ${email.toLowerCase()}` : `❌ No existe una cuenta con ${email}`);
}

main()
    .catch((error) => {
        console.error("❌", error.message);
        process.exitCode = 1;
    })
    .finally(() => db.pool.end());
