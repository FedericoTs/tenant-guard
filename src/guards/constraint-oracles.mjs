/**
 * Guard: constraints that answer questions across tenants.
 *
 * RLS hides *rows*. It does not hide *constraints* — and constraints are enforced
 * below RLS, over the whole table. So a schema can leak the one thing an attacker
 * usually wants first: **does this value exist in another tenant?**
 *
 *   • A **globally UNIQUE natural key** on a tenant-scoped table is an existence
 *     oracle. `users.email UNIQUE` means inserting `victim@corp.com` raises
 *     `duplicate key value violates unique constraint` even though RLS hides the
 *     row that caused it. That is account enumeration, and the same trick works
 *     silently through `ON CONFLICT DO NOTHING` (0 rows affected = it exists).
 *     The fix is a composite key: `UNIQUE (organization_id, email)`.
 *
 *   • A **single-column foreign key** between two tenant-scoped tables is the same
 *     shape one layer down: referential-integrity checks run with RLS **not
 *     applied**, so a child row can reference — and thereby confirm — a parent row
 *     in another tenant. The fix is a composite FK carrying the tenant:
 *     `FOREIGN KEY (organization_id, author) REFERENCES users (organization_id, id)`.
 *
 * Calibration, deliberately different for the two:
 *
 *   - The UNIQUE case **fails the build**. It is conclusive from the catalog (the
 *     constraint either includes the tenant column or it doesn't), and the impact
 *     is direct: anyone who can attempt an insert can test values.
 *   - The FK case is an **aggregated note, never a failure**. Composite tenant FKs
 *     are rare in practice, so failing on them would flag nearly every schema, and
 *     exploiting one needs both a guessable parent id and an insert that passes
 *     `WITH CHECK`. It is worth knowing and worth fixing; it is not worth blocking
 *     a merge over, and pretending otherwise would make the tool ignorable.
 *
 * Read-only: two catalog queries, no transaction, no probing.
 */
import { qualified } from './rls-proof.mjs';
import { DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'constraint-oracles',
  title: 'Constraints that reveal another tenant\'s rows',
  why: "RLS hides rows but not constraints, and constraints are enforced below it. A globally UNIQUE natural key on a tenant table lets anyone test whether a value (an email, a slug) exists in another tenant — enumeration through an error message. Single-column foreign keys between tenant tables are the same shape, since referential-integrity checks ignore RLS.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  allowlist: [], // "schema.table" or "schema.index_name" that is intentionally global
  // Types whose values are unguessable, so a global unique constraint over one of
  // them is not a practical oracle (you cannot enumerate random UUIDs).
  unguessableTypes: ['uuid'],
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Every UNIQUE index in `schemas`, with its columns and whether it's the PK. */
export function uniqueIndexSql(schemas) {
  const text = `
    select n.nspname   as schema,
           c.relname   as table,
           i.relname   as index,
           ix.indisprimary as is_primary,
           (select bool_or(k2.attnum = 0) from unnest(ix.indkey) as k2(attnum)) as has_expression,
           array_agg(a.attname order by k.ord) as columns,
           array_agg(format_type(a.atttypid, null) order by k.ord) as types
    from pg_catalog.pg_index ix
    join pg_catalog.pg_class i on i.oid = ix.indexrelid
    join pg_catalog.pg_class c on c.oid = ix.indrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    left join lateral unnest(ix.indkey) with ordinality as k(attnum, ord) on true
    left join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum
    where ix.indisunique
      and c.relkind in ('r', 'p')
      and n.nspname = any($1)
    group by 1, 2, 3, 4, ix.indkey
    order by 1, 2, 3`;
  return { text, values: [schemas] };
}

/** Every foreign key in `schemas`, with its child columns and referenced table. */
export function foreignKeySql(schemas) {
  const text = `
    select n.nspname  as schema,
           c.relname  as table,
           con.conname as name,
           array_agg(a.attname) as columns,
           fn.nspname as ref_schema,
           fc.relname as ref_table
    from pg_catalog.pg_constraint con
    join pg_catalog.pg_class c on c.oid = con.conrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_class fc on fc.oid = con.confrelid
    join pg_catalog.pg_namespace fn on fn.oid = fc.relnamespace
    join lateral unnest(con.conkey) as k(attnum) on true
    join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum
    where con.contype = 'f'
      and n.nspname = any($1)
    group by 1, 2, 3, 5, 6
    order by 1, 2, 3`;
  return { text, values: [schemas] };
}

/** Which tenant column (if any) a table carries, by priority. */
export function tenantColumnSql(schemas, tenantColumns) {
  const text = `
    select n.nspname as schema,
           c.relname as table,
           (select a.attname
              from pg_catalog.pg_attribute a
             where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
               and a.attname = any($2)
             order by array_position($2, a.attname)
             limit 1) as tenant_column
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r', 'p')
      and n.nspname = any($1)`;
  return { text, values: [schemas, tenantColumns] };
}

/**
 * Verdict for one UNIQUE index.
 * @returns {{status:'oracle'|'safe'|'skip', reason?:string}}
 */
export function classifyUniqueIndex({ isPrimary, hasExpression, columns = [], types = [], tenantColumn, unguessableTypes = DEFAULTS.unguessableTypes }) {
  if (!tenantColumn) return { status: 'skip', reason: 'table has no tenant column — not tenant-scoped data' };
  // A primary key is globally unique by design; saying so adds nothing.
  if (isPrimary) return { status: 'skip', reason: 'primary key' };
  // An expression index (lower(email)) can't be reasoned about from indkey alone.
  if (hasExpression || columns.some((c) => c == null)) return { status: 'skip', reason: 'expression index — cannot determine its columns' };
  if (columns.includes(tenantColumn)) return { status: 'safe' }; // correctly scoped
  // A single unguessable-type column is not a practical oracle: you cannot
  // enumerate random UUIDs, so "does this one exist" answers nothing useful.
  if (columns.length === 1 && unguessableTypes.includes((types[0] || '').toLowerCase())) {
    return { status: 'skip', reason: `single ${types[0]} column — values are unguessable, so it is not a practical oracle` };
  }
  return { status: 'oracle' };
}

/**
 * Verdict for one foreign key. Only a FK *between two tenant-scoped tables* that
 * doesn't carry the tenant is interesting; the tenant FK itself (org_id -> orgs)
 * is the correct pattern, not a finding.
 */
export function classifyForeignKey({ columns = [], childTenantColumn, parentTenantColumn }) {
  if (!childTenantColumn || !parentTenantColumn) return { status: 'skip' };
  if (columns.includes(childTenantColumn)) return { status: 'safe' }; // composite, carries the tenant
  if (columns.length === 1 && columns[0] === childTenantColumn) return { status: 'safe' };
  return { status: 'oracle' };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const q = async (text, values) => (await query(text, values)).rows;
  const skip = new Set(cfg.allowlist);

  const tc = tenantColumnSql(cfg.schemas, cfg.tenantColumns);
  const tenantOf = new Map();
  for (const r of await q(tc.text, tc.values)) tenantOf.set(`${r.schema}.${r.table}`, r.tenant_column);

  const violations = [];
  const notes = [];
  let scanned = 0;

  // ── unique-constraint oracles (a build failure) ────────────────────
  const ui = uniqueIndexSql(cfg.schemas);
  for (const r of await q(ui.text, ui.values)) {
    const id = `${r.schema}.${r.table}`;
    if (skip.has(id) || skip.has(`${r.schema}.${r.index}`) || skip.has(r.index)) continue;
    const tenantColumn = tenantOf.get(id);
    const verdict = classifyUniqueIndex({
      isPrimary: r.is_primary === true || r.is_primary === 't',
      hasExpression: r.has_expression === true || r.has_expression === 't',
      columns: r.columns || [],
      types: r.types || [],
      tenantColumn,
      unguessableTypes: cfg.unguessableTypes,
    });
    if (verdict.status === 'skip') continue;
    scanned++;
    if (verdict.status !== 'oracle') continue;
    const cols = (r.columns || []).map((c) => `"${c}"`).join(', ');
    violations.push({
      where: `${id} (${r.index})`,
      kind: 'unique-oracle',
      message:
        `UNIQUE ${cols} on a tenant-scoped table does not include "${tenantColumn}", so it is enforced ACROSS every tenant. ` +
        `Unique indexes are checked BELOW row-level security: inserting a value that already exists in another tenant raises "duplicate key value violates unique constraint" even though RLS hides the row that caused it. ` +
        `Anyone who can attempt an insert can therefore test whether a given value (an email, a slug, a phone number) exists in some other tenant — and ON CONFLICT DO NOTHING answers the same question silently, with no error at all`,
      fix:
        `Scope the constraint to the tenant so the same value can exist once per tenant:\n` +
        `        ALTER TABLE ${qualified(r.schema, r.table)} DROP CONSTRAINT ${r.index};\n` +
        `        ALTER TABLE ${qualified(r.schema, r.table)} ADD CONSTRAINT ${r.index}\n` +
        `          UNIQUE ("${tenantColumn}", ${cols});\n` +
        `      If the value is genuinely global by design (a public slug, a billing id), add "${id}" or "${r.schema}.${r.index}" to constraintOracles.allowlist[].`,
    });
  }

  // ── FK oracles (an aggregated note, never a failure) ───────────────
  const fk = foreignKeySql(cfg.schemas);
  const looseFks = [];
  for (const r of await q(fk.text, fk.values)) {
    const id = `${r.schema}.${r.table}`;
    if (skip.has(id) || skip.has(`${r.schema}.${r.name}`) || skip.has(r.name)) continue;
    const verdict = classifyForeignKey({
      columns: r.columns || [],
      childTenantColumn: tenantOf.get(id),
      parentTenantColumn: tenantOf.get(`${r.ref_schema}.${r.ref_table}`),
    });
    if (verdict.status === 'oracle') looseFks.push(`${id}.${(r.columns || []).join('+')} → ${r.ref_schema}.${r.ref_table}`);
  }
  if (looseFks.length > 0) {
    notes.push({
      where: `${looseFks.length} foreign key(s)`,
      message:
        `${looseFks.length} foreign key(s) between tenant-scoped tables do not carry the tenant column: ${looseFks.slice(0, 3).join('; ')}${looseFks.length > 3 ? `; +${looseFks.length - 3} more` : ''}. ` +
        `Referential-integrity checks run with RLS NOT applied, so a child row can reference — and thereby confirm the existence of — a parent row in another tenant. ` +
        `The fix is a composite FK that carries the tenant, e.g. FOREIGN KEY (organization_id, parent_id) REFERENCES parent (organization_id, id). ` +
        `Reported as a note rather than a failure: composite tenant FKs are rare, and exploiting one needs both a guessable parent id and an insert that passes WITH CHECK.`,
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
        ? `${violations.length} cross-tenant existence oracle(s) in ${new Set(violations.map((v) => v.where)).size} constraint(s)`
        : `${scanned} tenant unique constraint(s) checked; none leak across tenants` + (notes.length ? ` (${notes.length} note(s))` : ''),
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
