// =========================
// CREAR SUPER ADMIN INICIAL
// Uso: npm run create-admin -- "Nombre Completo" correo@ejemplo.com "Contrasena123"
// =========================

require("dotenv").config();

const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const db = require("./db");

const dbp = db.promise();

async function main() {
    const [fullname, email, password] = process.argv.slice(2);

    if (!fullname || !email || !password) {
        console.log('Uso: npm run create-admin -- "Nombre Completo" correo@ejemplo.com "Contrasena123"');
        process.exit(1);
    }

    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(password)) {
        console.log("❌ La contraseña debe tener al menos 8 caracteres, mayúsculas, minúsculas y números");
        process.exit(1);
    }

    const [roles] = await dbp.query("SELECT id FROM roles WHERE role_name = 'SUPER_ADMIN'");
    if (roles.length === 0) {
        throw new Error("No existe el rol SUPER_ADMIN. Ejecuta primero Database/sacm.sql");
    }

    const [existing] = await dbp.query("SELECT id FROM users WHERE email = ?", [email.toLowerCase()]);
    if (existing.length > 0) {
        console.log("❌ Ya existe un usuario con ese correo");
        process.exit(1);
    }

    const userId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 12);

    await dbp.query(
        "INSERT INTO users (id, fullname, email, password, role_id) VALUES (?, ?, ?, ?, ?)",
        [userId, fullname.trim(), email.toLowerCase(), hashedPassword, roles[0].id]
    );
    await dbp.query(
        "INSERT INTO user_profiles (id, user_id, department, profile_status) VALUES (?, ?, ?, 'ACTIVE')",
        [uuidv4(), userId, "Seguridad"]
    );

    console.log(`✅ Super admin creado: ${email.toLowerCase()}`);
}

main()
    .catch((error) => {
        console.error("❌ Error creando el admin:", error.message);
        process.exitCode = 1;
    })
    .finally(() => db.end());
