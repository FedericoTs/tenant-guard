/**
 * Guard: RLS policy drift — prove your security posture is in version control.
 *
 * The failure this exists for: a table's Row-Level Security can be turned on and
 * given policies **by hand in the Supabase dashboard** (or a psql one-off) and
 * never captured in a migration. When that happens the table's real security
 * posture is invisible to code review, absent from any fresh / CI database, and
 * editable in the UI with no diff, no reviewer, and no history. A permissive
 * policy that lets `anon` write a shared table can sit in production for months
 * and never appear in a single pull request.
 *
 * This guard compares what your migrations DECLARE (every `ENABLE ROW LEVEL
 * SECURITY` and `CREATE POLICY`, net of `DROP`/`DISABLE`) against what the
 * database ACTUALLY has (`pg_policies` + `pg_class.relrowsecurity`) and fails
 * the build on anything present in the database but not in a migration.
 *
 * It reads text (migrations) and runs a query (the catalog) — so, like
 * `rls-proof`, it needs a Postgres connection and skips cleanly without one.
 * The parse + diff are pure and unit-tested; the DB read is a couple of catalog
 * queries with no side effects at all (it never writes, and needs no
 * transaction).
 */

export const meta = {
  id: 'rls-drift',
  title: 'RLS policy version-control drift',
  why: 'Fails when the database has RLS enabled or policies that no migration declares — security posture that is invisible to code review and changeable in the dashboard with no history.',
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'], // user schema(s); Supabase-managed schemas (auth, storage, …) are excluded
  allowlist: [], // "schema.table" or "schema.table::policy_name" managed outside migrations on purpose
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Strip one layer of surrounding double-quotes from an identifier. */
export function stripQuotes(id) {
  const t = id.trim();
  return t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t;
}

/** Normalise a (possibly schema-qualified, possibly quoted) table ref to `schema.table` (default schema `public`). */
export function normalizeTable(raw) {
  const parts = raw.trim().split('.').map((p) => stripQuotes(p));
  const table = parts.pop();
  const schema = parts.length ? parts[0] : 'public';
  return `${schema}.${table}`;
}

const IDENT = `"[^"]+"|[A-Za-z0-9_]+`;
const TABLEREF = `(?:${IDENT})(?:\\.(?:${IDENT}))?`;

/**
 * The NET declared state across all migrations: which tables have RLS enabled,
 * and which policies exist — applying CREATE/DROP and ENABLE/DISABLE in order.
 * @param {{name:string, sql:string}[]} files
 * @returns {{ rlsEnabled: Set<string>, policies: Set<string> }}  policy ids are `schema.table::name`
 */
export function parseDeclaredState(files) {
  const rlsEnabled = new Set();
  const policies = new Set();
  const sorted = [...files].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  for (const { sql } of sorted) {
    const events = [];
    const scan = (re, make) => {
      let m;
      while ((m = re.exec(sql)) !== null) events.push({ i: m.index, ...make(m) });
    };
    scan(new RegExp(`create\\s+policy\\s+(?:if\\s+not\\s+exists\\s+)?(${IDENT})\\s+on\\s+(${TABLEREF})`, 'gi'),
      (m) => ({ type: 'create', id: `${normalizeTable(m[2])}::${stripQuotes(m[1])}` }));
    scan(new RegExp(`drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${IDENT})\\s+on\\s+(${TABLEREF})`, 'gi'),
      (m) => ({ type: 'drop', id: `${normalizeTable(m[2])}::${stripQuotes(m[1])}` }));
    scan(new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(${TABLEREF})\\s+enable\\s+row\\s+level\\s+security`, 'gi'),
      (m) => ({ type: 'enable', id: normalizeTable(m[1]) }));
    scan(new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(${TABLEREF})\\s+disable\\s+row\\s+level\\s+security`, 'gi'),
      (m) => ({ type: 'disable', id: normalizeTable(m[1]) }));

    events.sort((a, b) => a.i - b.i);
    for (const e of events) {
      if (e.type === 'create') policies.add(e.id);
      else if (e.type === 'drop') policies.delete(e.id);
      else if (e.type === 'enable') rlsEnabled.add(e.id);
      else if (e.type === 'disable') rlsEnabled.delete(e.id);
    }
  }
  return { rlsEnabled, policies };
}

/** Catalog query for the policies actually present, in the given schemas. */
export function actualPoliciesSql(schemas) {
  return {
    text: `select schemaname as schema, tablename as "table", policyname as name from pg_policies where schemaname = any($1)`,
    values: [schemas],
  };
}

/** Catalog query for the tables that actually have RLS enabled, in the given schemas. */
export function actualRlsSql(schemas) {
  return {
    text:
      `select n.nspname as schema, c.relname as "table" ` +
      `from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace ` +
      `where c.relkind = 'r' and c.relrowsecurity = true and n.nspname = any($1)`,
    values: [schemas],
  };
}

/**
 * Diff declared (migrations) vs actual (database). The build-failing signal is
 * whatever exists in the DATABASE but not in a migration — unreviewed posture.
 * The reverse (declared but absent here) is a note: it usually just means this
 * database hasn't had every migration applied.
 */
export function diffState(declared, actual, allowlist = []) {
  const allow = new Set(allowlist);
  const skipTable = (id) => allow.has(id) || allow.has(id.split('::')[0]);

  const undeclaredPolicies = [...actual.policies].filter((p) => !declared.policies.has(p) && !skipTable(p));
  const missingPolicies = [...declared.policies].filter((p) => !actual.policies.has(p) && !skipTable(p));
  const undeclaredRls = [...actual.rlsEnabled].filter((t) => !declared.rlsEnabled.has(t) && !allow.has(t));
  const missingRls = [...declared.rlsEnabled].filter((t) => !actual.rlsEnabled.has(t) && !allow.has(t));
  return { undeclaredPolicies, undeclaredRls, missingPolicies, missingRls };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

/**
 * Compare migrations (files) against the live catalog (via an injected query fn).
 * @param {(text:string, values?:any[]) => Promise<{rows:any[]}>} query
 * @param {{name:string, sql:string}[]} files  migration files
 * @param {object} config  see DEFAULTS
 */
export async function drift({ query, files, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const declared = parseDeclaredState(files);

  const pol = actualPoliciesSql(cfg.schemas);
  const rls = actualRlsSql(cfg.schemas);
  const actual = {
    policies: new Set((await query(pol.text, pol.values)).rows.map((r) => `${r.schema}.${r.table}::${r.name}`)),
    rlsEnabled: new Set((await query(rls.text, rls.values)).rows.map((r) => `${r.schema}.${r.table}`)),
  };

  const d = diffState(declared, actual, cfg.allowlist);
  const violations = [];
  for (const p of d.undeclaredPolicies) {
    const [table, name] = p.split('::');
    violations.push({
      where: table,
      message: `policy "${name}" exists in the database but is in NO migration — it was applied out-of-band (dashboard/psql) and is invisible to code review`,
      fix: `Capture it in a migration: write the exact CREATE POLICY for "${name}" ON ${table} into a new migration and commit it (then verify prod matches). If it is intentionally managed outside migrations, add "${p}" to rlsDrift.allowlist[].`,
    });
  }
  for (const t of d.undeclaredRls) {
    violations.push({
      where: t,
      message: `ROW LEVEL SECURITY is enabled on this table in the database but no migration declares it — the on/off state of your isolation is not in version control`,
      fix: `Add "ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;" to a migration (with its policies), or allowlist "${t}".`,
    });
  }

  const notes = [];
  for (const p of d.missingPolicies) notes.push({ where: p.split('::')[0], message: `migration declares policy "${p.split('::')[1]}" but this database doesn't have it — migrations may be unapplied here` });
  for (const t of d.missingRls) notes.push({ where: t, message: `migration enables RLS on ${t} but this database has it OFF — migrations unapplied, or it was disabled out-of-band` });

  const scanned = actual.policies.size + actual.rlsEnabled.size;
  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length === 0
        ? `${actual.policies.size} policy(ies) + ${actual.rlsEnabled.size} RLS table(s) all declared in migrations` + (notes.length ? `; ${notes.length} declared-but-absent (see notes)` : '')
        : `${violations.length} database RLS setting(s) not in any migration`,
  };
}

/**
 * CLI/programmatic entry: read the migration files, resolve a Postgres
 * connection from the environment, dynamically import `pg`, and run the diff.
 * SKIPS cleanly (never fails the build) with no database URL or no `pg`.
 * @param {object} config  see DEFAULTS, plus `migrationsDir` and optional `url`
 */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const { readdirSync, readFileSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');

  const dir = cfg.migrationsDir;
  if (!dir || !existsSync(dir)) {
    return OK({ skipped: true, reason: dir ? `migrations dir not found: ${dir}` : 'no migrations dir configured', summary: 'skipped — no migrations' });
  }
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).map((f) => ({ name: f, sql: readFileSync(join(dir, f), 'utf8') }));

  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) {
    return OK({ skipped: true, reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL) to compare migrations against a real database`, summary: 'skipped — no database' });
  }
  let pg;
  try {
    pg = await import('pg');
  } catch {
    return OK({ skipped: true, reason: 'Postgres driver not installed — run `npm i -D pg` to enable the RLS drift check', summary: 'skipped — pg not installed' });
  }

  const Client = pg.default?.Client ?? pg.Client;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    const query = (text, values) => client.query(text, values);
    return await drift({ query, files, config: cfg });
  } finally {
    await client.end();
  }
}
