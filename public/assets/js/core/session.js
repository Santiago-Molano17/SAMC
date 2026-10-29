import { api } from "./api.js";

const LEVEL = { USER: 1, ANALYST: 2, ADMIN: 3, SUPER_ADMIN: 4 };
const listeners = new Set();

let current = null;

export const session = {
    get user() {
        return current;
    },

    async load() {
        try {
            const { user } = await api.get("/auth/me");
            current = user;
        } catch {
            current = null;
        }
        return current;
    },

    set(user) {
        current = user;
        listeners.forEach((fn) => fn(current));
    },

    /** ¿El usuario actual tiene al menos este rol? */
    can(role) {
        return Boolean(current) && LEVEL[current.role] >= LEVEL[role];
    },

    onChange(fn) {
        listeners.add(fn);
        return () => listeners.delete(fn);
    },

    async logout() {
        try {
            await api.post("/auth/logout");
        } finally {
            current = null;
            location.href = "/login";
        }
    }
};
