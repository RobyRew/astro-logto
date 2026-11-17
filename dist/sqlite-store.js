export { memorySessionStore } from './store.js';
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
/**
 * SessionStore on a SQLite table: id TEXT PK, data TEXT (sealed blob),
 * created_at / expires_at INTEGER (ms), user_key TEXT (indexed).
 */
export function sqliteSessionStore(db, options = {}) {
    const table = options.table ?? 'logto_sessions';
    const c = {
        id: options.columns?.id ?? 'id',
        data: options.columns?.data ?? 'data',
        createdAt: options.columns?.createdAt ?? 'created_at',
        expiresAt: options.columns?.expiresAt ?? 'expires_at',
        userKey: options.columns?.userKey ?? 'user_key',
    };
    for (const name of [table, ...Object.values(c)]) {
        // Identifiers cannot be bound as parameters, so they are validated instead.
        if (!IDENT.test(name))
            throw new Error(`sqliteSessionStore: invalid identifier "${name}"`);
    }
    if (options.createTable) {
        db.exec(`CREATE TABLE IF NOT EXISTS ${table} (${c.id} TEXT PRIMARY KEY, ${c.data} TEXT NOT NULL, ` +
            `${c.createdAt} INTEGER NOT NULL, ${c.expiresAt} INTEGER NOT NULL, ${c.userKey} TEXT)`);
    }
    const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name);
    if (columns.length === 0)
        throw new Error(`sqliteSessionStore: table ${table} does not exist (pass createTable: true, or create it in a migration)`);
    if (!columns.includes(c.userKey)) {
        if (!options.createTable) {
            throw new Error(`sqliteSessionStore: table ${table} has no ${c.userKey} column. Add it with ` +
                `ALTER TABLE ${table} ADD COLUMN ${c.userKey} TEXT; CREATE INDEX ${table}_${c.userKey} ON ${table}(${c.userKey});`);
        }
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${c.userKey} TEXT`);
    }
    if (options.createTable)
        db.exec(`CREATE INDEX IF NOT EXISTS ${table}_${c.userKey} ON ${table}(${c.userKey})`);
    const get = db.prepare(`SELECT ${c.data} AS data, ${c.expiresAt} AS expiresAt FROM ${table} WHERE ${c.id} = ?`);
    const upsert = db.prepare(`INSERT INTO ${table} (${c.id}, ${c.data}, ${c.createdAt}, ${c.expiresAt}, ${c.userKey}) VALUES (?, ?, ?, ?, ?) ` +
        `ON CONFLICT(${c.id}) DO UPDATE SET ${c.data} = excluded.${c.data}, ${c.expiresAt} = excluded.${c.expiresAt}, ` +
        `${c.userKey} = excluded.${c.userKey}`);
    const del = db.prepare(`DELETE FROM ${table} WHERE ${c.id} = ?`);
    const delUser = db.prepare(`DELETE FROM ${table} WHERE ${c.userKey} = ?`);
    const prune = db.prepare(`DELETE FROM ${table} WHERE ${c.expiresAt} < ?`);
    return {
        load(id) {
            const row = get.get(id);
            if (!row || Number(row.expiresAt) < Date.now())
                return null;
            return row.data;
        },
        save(id, blob, expiresAt, userKey) {
            upsert.run(id, blob, Date.now(), expiresAt, userKey);
        },
        drop(id) {
            del.run(id);
        },
        dropUser(userKey) {
            delUser.run(userKey);
        },
        prune(now) {
            prune.run(now);
        },
    };
}
