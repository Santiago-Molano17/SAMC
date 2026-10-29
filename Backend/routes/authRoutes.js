const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const db = require("../db");

// =========================
// VALIDACIONES
// =========================

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function validatePassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return passwordRegex.test(password);
}

function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.trim().substring(0, 255);
}

// =========================
// REGISTER MEJORADO
// =========================

router.post("/register", async (req, res) => {
    try {
        const { fullname, email, password, password_confirm } = req.body;

        if (!fullname || !email || !password || !password_confirm) {
            return res.status(400).json({
                message: "Todos los campos son obligatorios"
            });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({
                message: "Email inválido"
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                message: "La contraseña debe tener al menos 8 caracteres, incluir mayúsculas, minúsculas y números"
            });
        }

        if (password !== password_confirm) {
            return res.status(400).json({
                message: "Las contraseñas no coinciden"
            });
        }

        if (fullname.length < 3 || fullname.length > 100) {
            return res.status(400).json({
                message: "El nombre debe tener entre 3 y 100 caracteres"
            });
        }

        const sanitizedFullname = sanitizeInput(fullname);
        const sanitizedEmail = sanitizeInput(email).toLowerCase();

        const checkUser = "SELECT * FROM users WHERE email = ?";

        db.query(checkUser, [sanitizedEmail], async (err, results) => {
            if (err) {
                return res.status(500).json({ message: "Error en la base de datos" });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: "El correo ya está registrado" });
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 12);

                const newUser = {
                    id: uuidv4(),
                    fullname: sanitizedFullname,
                    email: sanitizedEmail,
                    password: hashedPassword,
                    role_id: 4
                };

                const sql = `INSERT INTO users (id, fullname, email, password, role_id) VALUES (?, ?, ?, ?, ?)`;

                db.query(sql, [newUser.id, newUser.fullname, newUser.email, newUser.password, newUser.role_id], (err) => {
                    if (err) {
                        return res.status(500).json({ message: "Error al registrar el usuario" });
                    }

                    const profileId = uuidv4();
                    const profileSql = `INSERT INTO user_profiles (id, user_id, department, profile_status) VALUES (?, ?, ?, 'ACTIVE')`;
                    db.query(profileSql, [profileId, newUser.id, "General"]);

                    res.status(201).json({ message: "✅ Usuario registrado correctamente" });
                });
            } catch (hashError) {
                res.status(500).json({ message: "Error en el servidor" });
            }
        });
    } catch (error) {
        res.status(500).json({ message: "Error en el servidor" });
    }
});

// =========================
// LOGIN MEJORADO
// =========================

router.post("/login", (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email y contraseña requeridos" });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ message: "Email inválido" });
        }

        const sanitizedEmail = sanitizeInput(email).toLowerCase();

        const sql = `SELECT users.*, roles.role_name FROM users INNER JOIN roles ON users.role_id = roles.id WHERE email = ?`;

        db.query(sql, [sanitizedEmail], async (err, results) => {
            if (err) {
                return res.status(500).json({ message: "Error en la base de datos" });
            }

            if (results.length === 0) {
                return res.status(401).json({ message: "Email o contraseña incorrectos" });
            }

            const user = results[0];

            try {
                const validPassword = await bcrypt.compare(password, user.password);

                if (!validPassword) {
                    return res.status(401).json({ message: "Email o contraseña incorrectos" });
                }

                const token = jwt.sign(
                    { id: user.id, role: user.role_name, email: user.email },
                    process.env.JWT_SECRET,
                    { expiresIn: "24h", issuer: "SACM", audience: "SACM-APP" }
                );

                const updateLoginSql = "UPDATE user_profiles SET last_login = NOW() WHERE user_id = ?";
                db.query(updateLoginSql, [user.id]);

                res.json({
                    message: "✅ Login exitoso",
                    token,
                    user: {
                        id: user.id,
                        fullname: user.fullname,
                        email: user.email,
                        role: user.role_name
                    }
                });
            } catch (bcryptError) {
                res.status(500).json({ message: "Error en el servidor" });
            }
        });
    } catch (error) {
        res.status(500).json({ message: "Error en el servidor" });
    }
});

// =========================
// VERIFY TOKEN
// =========================

router.post("/verify", (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({ valid: false, message: "Token requerido" });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({ valid: false, message: "Token inválido o expirado" });
            }

            res.json({ valid: true, user: decoded });
        });
    } catch (error) {
        res.status(500).json({ valid: false, message: "Error verificando token" });
    }
});

module.exports = router;