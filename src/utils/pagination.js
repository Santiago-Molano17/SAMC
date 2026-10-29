const { z } = require("zod");

const paginationSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(20)
});

function paginate(query) {
    const { page, pageSize } = paginationSchema.parse(query);
    return { page, pageSize, limit: pageSize, offset: (page - 1) * pageSize };
}

const pageResult = (items, total, { page, pageSize }) => ({
    items,
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize))
});

module.exports = { paginate, pageResult };
