const mysql = require("mysql2/promise");
const env = require("./env");

const pool = mysql.createPool({
    host: env.DB_HOST,
    port: env.DB_PORT,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    database: env.DB_NAME,
    connectionLimit: 10,
    charset: "utf8mb4",
    timezone: "Z",
    dateStrings: false,
    supportBigNumbers: true,
    bigNumberStrings: false
});

// Todas las fechas se manejan en UTC (el navegador las muestra en hora local)
pool.pool.on("connection", (connection) => {
    connection.query("SET time_zone = '+00:00'");
});

/** Ejecuta una consulta parametrizada y devuelve las filas */
async function query(sql, params = []) {
    const [rows] = await pool.query(sql, params);
    return rows;
}

/** Devuelve la primera fila o null */
async function queryOne(sql, params = []) {
    const rows = await query(sql, params);
    return rows[0] || null;
}

/** Ejecuta varias operaciones en una transacción */
async function transaction(work) {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const result = await work({
            query: async (sql, params = []) => (await connection.query(sql, params))[0]
        });
        await connection.commit();
        return result;
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        connection.release();
    }
}

module.exports = { pool, query, queryOne, transaction };
