const { z } = require("zod");

const email = z.string().trim().toLowerCase().email("Correo inválido").max(150);

const password = z.string()
    .min(8, "Mínimo 8 caracteres")
    .max(128, "Máximo 128 caracteres")
    .regex(/[a-z]/, "Debe incluir una minúscula")
    .regex(/[A-Z]/, "Debe incluir una mayúscula")
    .regex(/\d/, "Debe incluir un número");

const fullName = z.string().trim().min(3, "Mínimo 3 caracteres").max(100, "Máximo 100 caracteres");

const registerSchema = z.object({
    fullName,
    email,
    password,
    confirmPassword: z.string()
}).refine((data) => data.password === data.confirmPassword, {
    message: "Las contraseñas no coinciden",
    path: ["confirmPassword"]
});

const loginSchema = z.object({
    email,
    password: z.string().min(1, "Ingresa tu contraseña").max(128)
});

module.exports = { email, password, fullName, registerSchema, loginSchema };
