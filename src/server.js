const env = require("./config/env");
const db = require("./config/database");
const app = require("./app");
const queue = require("./analysis/queue");
const { describeIntegrations } = require("./analysis/providers");

async function start() {
    try {
        await db.query("SELECT 1 FROM schema_migrations LIMIT 1");
    } catch (error) {
        const hint = error.code === "ER_BAD_DB_ERROR" || error.code === "ER_NO_SUCH_TABLE"
            ? "Ejecuta primero: npm run db:setup"
            : error.message;
        console.error(`❌ No se pudo conectar a la base de datos "${env.DB_NAME}". ${hint}`);
        process.exit(1);
    }

    app.listen(env.PORT, () => {
        console.log(`\n🛡️  SACM v2 listo en http://localhost:${env.PORT}`);
        console.log(`   Base de datos: ${env.DB_NAME} · Entorno: ${env.NODE_ENV}`);
        for (const integration of describeIntegrations().filter((i) => i.type === "external")) {
            const state = integration.enabled ? "activa" : `inactiva (configura ${integration.requiresKey})`;
            console.log(`   ${integration.enabled ? "●" : "○"} ${integration.name}: ${state}`);
        }
        console.log("");
    });

    await queue.resumePending();
}

start();
