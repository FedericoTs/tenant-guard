/**
 * Guard: tenant data copied into a table that isn't protected like the source.
 *
 * A trigger on a tenant table writes an audit row, an outbox event, a
 * denormalised cache. The source table has flawless RLS. The **destination**
 * usually has no tenant column at all — so every tenant-aware guard here walks
 * straight past it, and every tenant's activity sits in one readable table:
 *
 *     create table audit_log (id serial primary key, actor text, detail text);
 *     grant select on audit_log to authenticated;          -- no RLS, no tenant column
 *     create trigger t_log after insert on invoices
 *       for each row execute function log_invoice();       -- writes into audit_log
 *
 * Verified: as tenant A, `invoices` correctly returns one row while `audit_log`
 * returns both tenants' rows, and `rls-proof` and `anon-reads` both report green.
 * The data left the protected table and nothing followed it.
 *
 * Detection has to read the function body: plpgsql is not parsed at creation
 * time, so — unlike a policy expression — a trigger function records **no
 * `pg_depend` entry** for the tables it writes. That's a documented limitation of
 * this check, not an oversight: a target assembled dynamically won't be seen.
 *
 * Conclusive case only, so a finding is never a guess: the destination is
 * readable by your app role **and RLS is off on it**. If RLS is on, the other
 * guards judge it on its merits; if the role can't read it, nothing is exposed.
 */
import {
  qualified,
  safeRole,
  introspectionSql,
  planTables,
  DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';

export const meta = {
  id: 'shadow-tables',
  title: 'Tenant data copied into an unprotected table',
  why: "A trigger on a tenant table writes to an audit log, outbox or cache that has no tenant column and no RLS — so every tenant's activity lands in one table anyone can read, and every tenant-column-based check walks straight past it because the destination has no tenant column to key on.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  role: PROOF_DEFAULTS.role,
  allowlist: [], // "schema.table" destinations that are intentionally unscoped
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Non-internal triggers in `schemas`, with the body of the function they call. */
export function triggersSql(schemas) {
  const text = `
    select n.nspname  as schema,
           c.relname  as table,
           t.tgname   as trigger,
           fn.nspname as fn_schema,
           p.proname  as fn_name,
           p.prosrc   as body,
           p.prosecdef as is_definer
    from pg_catalog.pg_trigger t
    join pg_catalog.pg_class c on c.oid = t.tgrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_proc p on p.oid = t.tgfoid
    join pg_catalog.pg_namespace fn on fn.oid = p.pronamespace
    where not t.tgisinternal
      and n.nspname = any($1)
    order by 1, 2, 3`;
  return { text, values: [schemas] };
}

/** RLS status, tenant column and the app role's SELECT grant for a set of tables. */
export function destinationSql(qualifiedNames, tenantColumns, role) {
  const text = `
    select n.nspname as schema,
           c.relname as table,
           c.relrowsecurity as rls_enabled,
           pg_catalog.has_table_privilege($3::text, c.oid, 'SELECT') as can_select,
           (select a.attname
              from pg_catalog.pg_attribute a
             where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
               and a.attname = any($2)
             limit 1) as tenant_column
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where (n.nspname || '.' || c.relname) = any($1)
      and c.relkind in ('r', 'p')`;
  return { text, values: [qualifiedNames, tenantColumns, role] };
}

/**
 * Tables a trigger function writes to, read out of its body.
 *
 * plpgsql bodies are opaque to the catalog, so this is text analysis — and it is
 * deliberately literal: an `INSERT INTO`/`UPDATE` naming a table directly. A
 * dynamically-assembled target is not found, which is stated as a limitation
 * rather than papered over.
 */
export function writeTargets(body, defaultSchema = 'public') {
  const s = String(body || '');
  const out = new Set();
  const add = (schema, table) => {
    if (!table) return;
    const t = table.replace(/"/g, '').toLowerCase();
    // NEW/OLD are trigger records, not tables.
    if (['new', 'old'].includes(t)) return;
    out.add(`${(schema || defaultSchema).replace(/"/g, '').toLowerCase()}.${t}`);
  };
  for (const m of s.matchAll(/\binsert\s+into\s+(?:("?[\w$]+"?)\s*\.\s*)?("?[\w$]+"?)/gi)) add(m[1], m[2]);
  for (const m of s.matchAll(/\bupdate\s+(?:("?[\w$]+"?)\s*\.\s*)?("?[\w$]+"?)\s+set\b/gi)) add(m[1], m[2]);
  return [...out];
}

/**
 * Verdict for one destination table.
 * @returns {{status:'leak'|'safe', message?:string, fix?:string}}
 */
export function classifyDestination({ schema, table, rlsEnabled, canSelect, tenantColumn, sources = [], role = 'authenticated' }) {
  if (!canSelect) return { status: 'safe' };   // the role can't read it — nothing exposed
  if (rlsEnabled) return { status: 'safe' };   // protected; the other guards judge it on its merits
  const via = sources.join(', ');
  return {
    status: 'leak',
    message:
      `${schema}.${table} receives rows derived from tenant data (written by a trigger on ${via}), "${role}" can read it, and it has NO row-level security` +
      (tenantColumn ? ` — despite carrying a "${tenantColumn}" column that could scope it` : ` and no tenant column to scope it by`) +
      `. The data left a protected table and nothing followed it: every tenant's activity is readable here by any logged-in user, and the tenant-column guards walk past it because there is nothing to key on`,
    fix:
      `Protect the destination like the source it copies from:\n` +
      (tenantColumn
        ? `        ALTER TABLE ${qualified(schema, table)} ENABLE ROW LEVEL SECURITY;\n` +
          `        CREATE POLICY tenant_isolation ON ${qualified(schema, table)}\n` +
          `          USING ("${tenantColumn}" = current_setting('app.current_tenant'));\n`
        : `        -- add the tenant to the row so it CAN be scoped, then:\n` +
          `        ALTER TABLE ${qualified(schema, table)} ADD COLUMN organization_id text;\n` +
          `        ALTER TABLE ${qualified(schema, table)} ENABLE ROW LEVEL SECURITY;\n` +
          `        CREATE POLICY tenant_isolation ON ${qualified(schema, table)}\n` +
          `          USING (organization_id = current_setting('app.current_tenant'));\n`) +
      `      Or, if it is meant to be operator-only: REVOKE SELECT ON ${qualified(schema, table)} FROM ${role};`,
  };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;
  const skip = new Set(cfg.allowlist);

  // Which tables hold tenant data — those are the sources worth following.
  const intro = introspectionSql(cfg.schemas, cfg.tenantColumns, role);
  const tenantTables = new Set(planTables(await q(intro.text, intro.values), cfg.tenantColumns).map((t) => `${t.schema}.${t.table}`));
  if (tenantTables.size === 0) {
    return OK({ skipped: true, reason: `no tenant-column tables in ${cfg.schemas.join(', ')}`, summary: 'skipped — no tenant tables' });
  }

  const tg = triggersSql(cfg.schemas);
  const triggers = (await q(tg.text, tg.values)).filter((t) => tenantTables.has(`${t.schema}.${t.table}`));
  if (triggers.length === 0) {
    return OK({ skipped: true, reason: 'no triggers on tenant tables', summary: 'skipped — no triggers on tenant tables' });
  }

  // destination -> which tenant tables feed it
  const feeds = new Map();
  for (const t of triggers) {
    for (const dest of writeTargets(t.body, t.schema)) {
      // Only the trigger's OWN table is skipped. A destination that happens to
      // carry a tenant column is still worth checking: this finding is
      // structural (a trigger WILL fill it), where rls-proof is behavioural and
      // reports "cannot prove" on the empty outbox that hasn't been drained yet.
      if (dest === `${t.schema}.${t.table}`) continue;
      if (skip.has(dest)) continue;
      if (!feeds.has(dest)) feeds.set(dest, new Set());
      feeds.get(dest).add(`${t.schema}.${t.table}`);
    }
  }
  if (feeds.size === 0) {
    return OK({ scanned: 0, summary: 'no triggers on tenant tables write to an unguarded destination' });
  }

  const names = [...feeds.keys()];
  const ds = destinationSql(names, cfg.tenantColumns, role);
  const rows = await q(ds.text, ds.values);

  const violations = [];
  const notes = [];
  let scanned = 0;

  for (const r of rows) {
    const id = `${r.schema}.${r.table}`;
    scanned++;
    const verdict = classifyDestination({
      schema: r.schema,
      table: r.table,
      rlsEnabled: r.rls_enabled === true || r.rls_enabled === 't',
      canSelect: r.can_select === true || r.can_select === 't',
      tenantColumn: r.tenant_column,
      sources: [...(feeds.get(id) || [])],
      role,
    });
    if (verdict.status === 'leak') {
      violations.push({ where: id, kind: 'shadow', message: verdict.message, fix: verdict.fix });
    }
  }

  // Destinations named in a body that don't resolve to a real table (dynamic SQL,
  // a temp table, a typo). Say so rather than silently dropping them.
  const found = new Set(rows.map((r) => `${r.schema}.${r.table}`));
  const unresolved = names.filter((n) => !found.has(n));
  if (unresolved.length > 0) {
    notes.push({
      where: 'trigger bodies',
      message: `${unresolved.length} write target(s) named in a trigger body could not be resolved to a table (${unresolved.slice(0, 3).join(', ')}). plpgsql bodies are text, so a dynamically-assembled destination cannot be followed — check those by hand.`,
    });
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length > 0
        ? `${violations.length} unprotected table(s) receiving tenant data from a trigger`
        : `${scanned} trigger destination(s) checked; all protected or unreadable`,
  };
}

/** CLI/programmatic entry: resolve a connection, import `pg`, run the check. */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) return OK({ skipped: true, reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL)`, summary: 'skipped — no database' });
  let pg;
  try {
    pg = await import('pg');
  } catch {
    return OK({ skipped: true, reason: 'Postgres driver not installed — run `npm i -D pg`', summary: 'skipped — pg not installed' });
  }
  const Client = pg.default?.Client ?? pg.Client;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    return await check({ query: (text, values) => client.query(text, values), config: cfg });
  } finally {
    await client.end();
  }
}
