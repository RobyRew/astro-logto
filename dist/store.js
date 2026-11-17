/** In-memory store for tests and local experiments. */
export function memorySessionStore() {
    const rows = new Map();
    return {
        load: (id) => {
            const row = rows.get(id);
            return row && row.expiresAt >= Date.now() ? row.blob : null;
        },
        save: (id, blob, expiresAt, userKey) => void rows.set(id, { blob, expiresAt, userKey }),
        drop: (id) => void rows.delete(id),
        dropUser: (userKey) => {
            for (const [id, row] of rows)
                if (row.userKey === userKey)
                    rows.delete(id);
        },
        prune: (now) => {
            for (const [id, row] of rows)
                if (row.expiresAt < now)
                    rows.delete(id);
        },
        size: () => rows.size,
        rows: () => rows,
    };
}
