const path = require("path");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const env = require("./config/env");
const { apiLimiter } = require("./middleware/rateLimit");
const { notFoundHandler, errorHandler } = require("./middleware/errorHandler");

const authRoutes = require("./modules/auth/auth.routes");
const profileRoutes = require("./modules/profile/profile.routes");
const { publicRouter: userRoutes, adminRouter: adminUserRoutes } = require("./modules/users/users.routes");
const analysesRoutes = require("./modules/analyses/analyses.routes");
const analyticsRoutes = require("./modules/analytics/analytics.routes");
const casesRoutes = require("./modules/cases/cases.routes");
const auditRoutes = require("./modules/audit/audit.routes");
const systemRoutes = require("./modules/system/system.routes");

const app = express();
const publicDir = path.join(env.rootDir, "public");

app.disable("x-powered-by");
app.set("trust proxy", "loopback");

app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            "default-src": ["'self'"],
            // Sin scripts en línea ni de terceros: cualquier XSS inyectado no se ejecuta
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "blob:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "object-src": ["'none'"],
            "frame-ancestors": ["'none'"],
            "form-action": ["'self'"],
            "upgrade-insecure-requests": env.isProduction ? [] : null
        }
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

// ----- API -----
const api = express.Router();
api.use(apiLimiter);
api.get("/health", (req, res) => res.json({ status: "ok", version: "2.0.0" }));
api.use("/auth", authRoutes);
api.use("/profile", profileRoutes);
api.use("/users", userRoutes);
api.use("/analyses", analysesRoutes);
api.use("/analytics", analyticsRoutes);
api.use("/cases", casesRoutes);
api.use("/admin/users", adminUserRoutes);
api.use("/admin/audit", auditRoutes);
api.use("/system", systemRoutes);
api.use(notFoundHandler);

app.use("/api", (req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
}, api);

// ----- Librerías del frontend servidas localmente (sin CDNs) -----
const vendor = (pkg, sub = "") => path.join(env.rootDir, "node_modules", pkg, sub);
app.use("/vendor/chart.js", express.static(vendor("chart.js", "dist"), { maxAge: "7d" }));
app.use("/vendor/fonts/inter", express.static(vendor("@fontsource-variable/inter"), { maxAge: "30d" }));
app.use("/vendor/fonts/jetbrains-mono", express.static(vendor("@fontsource-variable/jetbrains-mono"), { maxAge: "30d" }));

// ----- Frontend -----
app.use(express.static(publicDir, {
    extensions: ["html"],
    maxAge: env.isProduction ? "1h" : 0,
    // En desarrollo el navegador siempre revalida, así los cambios de CSS/JS se ven al recargar
    setHeaders: (res) => { if (!env.isProduction) res.set("Cache-Control", "no-cache"); }
}));
app.get("/app", (req, res) => res.sendFile(path.join(publicDir, "app.html")));

app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
