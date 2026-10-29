const { badRequest } = require("../utils/errors");

/**
 * Valida req.body, req.query o req.params con un esquema zod.
 * El resultado validado queda en req.valid[source].
 */
const validate = (schema, source = "body") => (req, res, next) => {
    const result = schema.safeParse(req[source] ?? {});

    if (!result.success) {
        const fields = {};
        for (const issue of result.error.issues) {
            const key = issue.path.join(".") || "_";
            fields[key] = fields[key] || issue.message;
        }
        return next(badRequest("Revisa los datos enviados", fields));
    }

    req.valid = { ...(req.valid || {}), [source]: result.data };
    next();
};

module.exports = { validate };
