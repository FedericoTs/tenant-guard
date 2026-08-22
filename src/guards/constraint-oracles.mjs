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
 *   • An **EXCLUDE constraint** is the same oracle wearing a different error
 *     message. `EXCLUDE (slug WITH =)` is a unique key; `EXCLUDE USING gist
 *     (room_id WITH =, during WITH &&)` answers "is that room booked then?"
 *     across tenants. Measured in pglite: as tenant A, with 0 rows visible,
 *     inserting tenant B's slug raises `conflicting key value violates exclusion
 *     constraint`. These live in pg_index with `indisunique = false`, which is
 *     why a `where indisunique` filter never saw them.
 *
 *   • A **single-column foreign key** between two tenant-scoped tables is the same
 *     shape one layer down: referential-integrity checks run with RLS **not
 *     applied**, so a child row can reference — and thereby confirm — a parent row
 *     in another tenant. The fix is a composite FK carrying the tenant:
 *     `FOREIGN KEY (organization_id, author) REFERENCES users (organization_id, id)`.
 *
 * Calibration, deliberately different for each:
 *
 *   - The UNIQUE/EXCLUDE case **fails the build**. It is conclusive from the
 *     catalog (the constraint either includes the tenant column or it doesn't),
 *     and the impact is direct: anyone who can attempt an insert can test values.
 *   - Except where the value cannot be enumerated. A key made only of unguessable
 *     columns (uuids, or a column whose DEFAULT is a random generator) yields one
 *     bit about a pairing the attacker already holds; it is never a way in. Those
 *     are skipped, and the reason is stated.
 *   - A single-column global unique on a **bearer secret** (`token`, `key_hash`)
 *     is a **note that argues the opposite way**: the credential is looked up with
 *     no tenant in hand, so global uniqueness is what keeps that lookup
 *     unambiguous. Scoping it to the tenant — the advice this guard used to emit —
 *     was measured to let `token='tok-1'` resolve to two organizations at once.
 *   - The FK case is an **aggregated note, never a failure**. Composite tenant FKs
 *     are rare in practice, so failing on them would flag nearly every schema, and
 *     exploiting one needs both a guessable parent id and an insert that passes
 *     `WITH CHECK`. It is worth knowing and worth fixing; it is not worth blocking
 *     a merge over, and pretending otherwise would make the tool ignorable.
 *   - Anything the catalog cannot settle (an expression index whose expression
 *     names no column we recognise) is a note saying so. A skip is not a pass, and
 *     the summary used to read "none leak across tenants" over constraints it had
 *     never looked at.
 *
 * Read-only: three catalog queries, no transaction, no probing.
 */
import { qualified, quoteIdent } from './rls-proof.mjs';
import { DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'constraint-oracles',
  title: 'Constraints that reveal another tenant\'s rows',
  why: "RLS hides rows but not constraints, and constraints are enforced below it. A globally UNIQUE natural key on a tenant table lets anyone test whether a value (an email, a slug) exists in another tenant — enumeration through an error message. EXCLUDE constraints are the same thing with a different error message, and single-column foreign keys between tenant tables are the same shape one layer down, since referential-integrity checks ignore RLS.",
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
// NOTE: the two lists below are deliberately module constants and NOT DEFAULTS
// keys. Every DEFAULTS key has to be plumbed through resolveOraclesConfig() in
// src/config.mjs (test/config-reachability.test.mjs enforces that), and this file
// is the only one this change is allowed to touch. They are narrow enough that
// nobody should need to retune them; widening either one only ever suppresses
// findings, which is the direction that needs a human, not a config file.

/**
 * Column DEFAULTs that produce an unguessable value. Evidence that the column
 * holds a random secret whatever its declared type — `token text DEFAULT
 * gen_random_uuid()::text` is exactly as unenumerable as a `uuid` column, and the
 * old type-only test failed the build on it. `nextval` is pointedly absent:
 * sequence values are the most guessable thing in a database.
 */
const RANDOM_DEFAULT_RE = /\b(gen_random_uuid|gen_random_bytes|uuid_generate_v[145]|uuid_generate_v1mc|nanoid)\s*\(/i;

/**
 * Single-column unique keys whose name says "this is a bearer credential".
 * These get a note that says KEEP the global constraint, because a credential is
 * looked up before any tenant is known. Kept deliberately short — `code`, `slug`
 * and `email` are NOT here and must keep failing.
 */
const SECRET_COLUMN_RE = /^(token|secret|key_hash|hashed_key|api_key|access_key|access_token|refresh_token|session_token)$/i;

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Every UNIQUE **or EXCLUDE** index in `schemas`, with its columns, whether it is
 * the PK, and — the part the fix text depends on — whether a pg_constraint row
 * actually backs it.
 *
 * That last bit matters because `CREATE UNIQUE INDEX` (what Prisma and Drizzle
 * emit) creates no constraint, so `ALTER TABLE ... DROP CONSTRAINT <index>` errors
 * with `constraint "users_email_idx" of relation "users" does not exist` and the
 * developer is left with the oracle they came to fix. Measured on pglite: of the
 * three unique objects in a scratch schema, only the two written as table
 * constraints had a conindid match.
 *
 * No GROUP BY: the column/type arrays come from correlated subqueries instead,
 * because grouping would have to include `ix.indexprs`, and pg_node_tree has no
 * equality operator to group by.
 */
export function uniqueIndexSql(schemas) {
  const text = `
    select n.nspname   as schema,
           c.relname   as table,
           i.relname   as index,
           ix.indisprimary as is_primary,
           ix.indisexclusion as is_exclusion,
           (con.oid is not null) as constraint_backed,
           con.conname as constraint_name,
           case when con.oid is not null then pg_get_constraintdef(con.oid) end as constraint_def,
           pg_get_indexdef(ix.indexrelid) as index_def,
           pg_get_expr(ix.indexprs, ix.indrelid) as expr,
           (select bool_or(k2.attnum = 0) from unnest(ix.indkey) as k2(attnum)) as has_expression,
           (select array_agg(a.attname order by k.ord)
              from unnest(ix.indkey) with ordinality as k(attnum, ord)
              left join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum) as columns,
           (select array_agg(format_type(a.atttypid, null) order by k.ord)
              from unnest(ix.indkey) with ordinality as k(attnum, ord)
              left join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum) as types
    from pg_catalog.pg_index ix
    join pg_catalog.pg_class i on i.oid = ix.indexrelid
    join pg_catalog.pg_class c on c.oid = ix.indrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    left join pg_catalog.pg_constraint con
           on con.conindid = ix.indexrelid and con.contype in ('p', 'u', 'x')
    where (ix.indisunique or ix.indisexclusion)
      and c.relkind in ('r', 'p')
      and n.nspname = any($1)
    order by 1, 2, 3`;
  return { text, values: [schemas] };
}

/**
 * Every column in `schemas` with its type and DEFAULT expression. Two uses:
 * resolving which columns an expression index actually reads, and spotting a
 * random-generator default that makes a `text` column as unguessable as a uuid.
 */
export function columnFactsSql(schemas) {
  const text = `
    select n.nspname as schema,
           c.relname as table,
           a.attname as column,
           format_type(a.atttypid, null) as type,
           pg_get_expr(ad.adbin, ad.adrelid) as default_expr
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    left join pg_catalog.pg_attrdef ad on ad.adrelid = a.attrelid and ad.adnum = a.attnum
    where c.relkind in ('r', 'p')
      and n.nspname = any($1)
      and a.attnum > 0
      and not a.attisdropped`;
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
 * Identifiers an index expression mentions, intersected with the table's real
 * columns. `pg_get_expr` renders column references as plain identifiers, quoted
 * only when they need it, so tokenising and intersecting is exact for the shapes
 * that occur: `lower(email)` -> ['email'],
 * `COALESCE(ref, '000…'::uuid)` -> ['ref'].
 *
 * Only ever used to make a verdict *softer* (safe, or skip), so the one way it
 * can be wrong — a string literal that happens to spell a column name — errs
 * toward silence rather than toward a false failure.
 */
export function expressionColumns(expr, columnNames = []) {
  if (typeof expr !== 'string' || expr.length === 0) return [];
  const tokens = new Set(
    (expr.match(/"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*/g) || [])
      .map((t) => (t.startsWith('"') ? t.slice(1, -1).replace(/""/g, '"') : t)),
  );
  return columnNames.filter((name) => tokens.has(name));
}

/** True when a column DEFAULT produces an unguessable value. */
export function hasRandomDefault(defaultExpr) {
  return typeof defaultExpr === 'string' && RANDOM_DEFAULT_RE.test(defaultExpr);
}

/**
 * Verdict for one UNIQUE or EXCLUDE index.
 * @returns {{status:'oracle'|'safe'|'skip'|'note', reason?:string, kind?:string}}
 */
export function classifyUniqueIndex({
  isPrimary,
  hasExpression,
  columns = [],
  types = [],
  expr = null,
  tenantColumn,
  unguessableTypes = DEFAULTS.unguessableTypes,
  columnTypes = null,     // { name: type } for the table — lets us reason about `expr`
  columnDefaults = null,  // { name: defaultExpr } for the table
}) {
  if (!tenantColumn) return { status: 'skip', reason: 'table has no tenant column — not tenant-scoped data' };
  // A primary key is globally unique by design; saying so adds nothing.
  if (isPrimary) return { status: 'skip', reason: 'primary key' };

  // Tenant-in-the-key wins before anything else. This test used to sit BELOW the
  // expression bail-out, which meant the *correct* composite forms — `UNIQUE
  // (organization_id, lower(email))` (indkey `2 0`) and `EXCLUDE (organization_id
  // WITH =, room_id WITH =, slot WITH =)` — vanished from the report entirely
  // instead of being counted as safe. Moving it up only adds an early exit, so it
  // cannot turn anything into a new failure.
  if (columns.includes(tenantColumn)) return { status: 'safe' };

  const isExpression = hasExpression === true || columns.some((c) => c == null);
  if (isExpression) {
    const known = columnTypes ? Object.keys(columnTypes) : [];
    const referenced = expressionColumns(expr, known);
    // `lower(organization_id || ':' || email)` is tenant-scoped in effect.
    if (referenced.includes(tenantColumn)) return { status: 'safe' };
    if (referenced.length === 0) {
      // Cannot tell what it covers. Say that; do not report it as checked.
      return { status: 'note', kind: 'unanalysed', reason: 'expression index — could not resolve which columns it covers' };
    }
    if (referenced.every((c) => unguessableTypes.includes((columnTypes[c] || '').toLowerCase())
      || hasRandomDefault(columnDefaults?.[c]))) {
      return { status: 'skip', reason: `expression over unguessable column(s) (${referenced.join(', ')}) — not a practical oracle` };
    }
    // `create unique index on users (lower(email))` — the standard
    // case-insensitive-email idiom, and a live enumeration oracle. Verified in
    // pglite: tenant A sees 0 rows, and inserting the victim's address still
    // raises 23505 naming this index.
    return { status: 'oracle' };
  }

  // A key made ENTIRELY of unguessable columns is not an enumeration primitive.
  // The single-uuid case was already exempt; the composite one — `UNIQUE (team_id
  // uuid, user_id uuid)`, the ordinary join-table shape — was not, and failed the
  // build on correct code. Measured: the collision only fires for someone who
  // already holds BOTH uuids, and neither is visible across tenants, so it
  // confirms a pairing they already know. Mixed keys stay oracles: once one uuid
  // is known, a guessable second column enumerates everything under it.
  const unguessableColumn = (c, i) =>
    unguessableTypes.includes((types[i] || '').toLowerCase()) || hasRandomDefault(columnDefaults?.[c]);
  if (columns.length > 0 && columns.every(unguessableColumn)) {
    const why = columns.length === 1
      ? `single ${types[0]} column — values are unguessable, so it is not a practical oracle`
      : `every column is unguessable (${columns.join(', ')}) — a collision only confirms a pairing the caller already holds`;
    return { status: 'skip', reason: why };
  }

  // A bearer credential is looked up with NO tenant in hand (`where token = $1`),
  // so global uniqueness is what makes that lookup resolve to one tenant. Scoping
  // it — what this guard used to demand — was measured to let the same token exist
  // in two organizations, turning a credential lookup into a multi-row one. Note,
  // never a failure, and the note argues for keeping the constraint.
  if (columns.length === 1 && SECRET_COLUMN_RE.test(columns[0] || '')) {
    return { status: 'note', kind: 'global-secret', reason: `"${columns[0]}" looks like a bearer credential` };
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
  // Carries the tenant — composite, or the FK simply IS the tenant column.
  // (A second `columns.length === 1 && columns[0] === childTenantColumn` branch
  // used to sit here; enumerating 496 inputs showed zero reach it that this test
  // does not already cover, since a one-element array whose element is `===` the
  // needle always satisfies includes().)
  if (columns.includes(childTenantColumn)) return { status: 'safe' };
  return { status: 'oracle' };
}

/**
 * Splice the tenant column in as the first key of a `CREATE INDEX` or
 * `EXCLUDE` definition Postgres handed us, so the emitted repair keeps the
 * original opclasses, operators, `WHERE` clause and access method.
 *
 * Verified against pglite: `EXCLUDE USING btree (slug WITH =)` ->
 * `EXCLUDE USING btree ("organization_id" WITH =, slug WITH =)` re-creates
 * cleanly, and `pg_get_constraintdef` reads it back identically.
 * Returns null when the definition does not have the expected `USING x (` shape,
 * so the caller can fall back rather than emit SQL that will not run.
 */
export function spliceTenantIntoDef(def, tenantColumn, { operator = null } = {}) {
  if (typeof def !== 'string') return null;
  const m = def.match(/\bUSING\s+[A-Za-z_][A-Za-z0-9_]*\s*\(/i);
  if (!m) return null;
  const at = m.index + m[0].length;
  const head = `${quoteIdent(tenantColumn)}${operator ? ` WITH ${operator}` : ''}, `;
  return def.slice(0, at) + head + def.slice(at);
}

/** The access method named in a `USING <method>` clause, or null. */
export function indexMethod(def) {
  const m = typeof def === 'string' ? def.match(/\bUSING\s+([A-Za-z_][A-Za-z0-9_]*)/i) : null;
  return m ? m[1].toLowerCase() : null;
}

/**
 * The remediation for one flagged constraint. Three shapes, because emitting the
 * wrong one leaves the oracle in place:
 *   - table constraint  -> ALTER TABLE ... DROP/ADD CONSTRAINT
 *   - plain unique index -> DROP INDEX / CREATE UNIQUE INDEX (there is no
 *     constraint of that name to drop; measured: DROP CONSTRAINT errors)
 *   - EXCLUDE constraint -> re-created from pg_get_constraintdef with the tenant
 *     spliced in as `<tenant> WITH =`; `ADD CONSTRAINT ... UNIQUE (...)` is not
 *     valid SQL for one.
 */
export function fixFor(r, tenantColumn) {
  const table = qualified(r.schema, r.table);
  // quoteIdent, not bare `"${c}"`: a column or index name can contain a double
  // quote, and the emitted statement has to survive it.
  const cols = (r.columns || []).filter(Boolean).map(quoteIdent).join(', ');
  const tenant = quoteIdent(tenantColumn);
  const tail =
    `\n      If the value is genuinely global by design (a public slug, a billing id), ` +
    `add "${r.schema}.${r.table}" or "${r.schema}.${r.index}" to constraintOracles.allowlist[].`;

  if (r.is_exclusion === true || r.is_exclusion === 't') {
    const name = quoteIdent(r.constraint_name || r.index);
    const spliced = spliceTenantIntoDef(r.constraint_def, tenantColumn, { operator: '=' });
    const method = indexMethod(r.constraint_def);
    // Under gist/spgist there is no equality operator class for an ordinary
    // scalar column, so `"organization_id" WITH =` does not compile without
    // btree_gist. Emitting the ALTER without it would hand the reader a
    // statement that cannot run. (Needs superuser, or a Supabase dashboard
    // extension toggle.)
    const ext = method && method !== 'btree'
      ? `        CREATE EXTENSION IF NOT EXISTS btree_gist;   -- superuser: ${method} has no "=" opclass for "${tenantColumn}" without it\n`
      : '';
    if (!spliced) {
      return `Re-create the constraint with "${tenantColumn}" WITH = as its first element, so the exclusion only applies within one tenant.${tail}`;
    }
    return (
      `Scope the exclusion to the tenant so it only compares rows of the same tenant:\n` +
      ext +
      `        ALTER TABLE ${table} DROP CONSTRAINT ${name};\n` +
      `        ALTER TABLE ${table} ADD CONSTRAINT ${name}\n` +
      `          ${spliced};` +
      tail
    );
  }

  if (r.constraint_backed === true || r.constraint_backed === 't') {
    const name = quoteIdent(r.constraint_name || r.index);
    return (
      `Scope the constraint to the tenant so the same value can exist once per tenant:\n` +
      `        ALTER TABLE ${table} DROP CONSTRAINT ${name};\n` +
      `        ALTER TABLE ${table} ADD CONSTRAINT ${name}\n` +
      `          UNIQUE (${tenant}, ${cols});` +
      tail
    );
  }

  // Plain `CREATE UNIQUE INDEX` — no pg_constraint row, so DROP CONSTRAINT fails.
  // Rebuild from pg_get_indexdef so opclasses, expressions and any WHERE clause
  // survive; fall back to a plain column list if the definition is an odd shape.
  const spliced = spliceTenantIntoDef(r.index_def, tenantColumn);
  // The fallback needs a real column list; an expression index has none, and
  // emitting `(… , )` would be worse than saying it in words.
  const create = spliced
    || (cols ? `CREATE UNIQUE INDEX ${quoteIdent(r.index)} ON ${table} (${tenant}, ${cols})` : null);
  if (!create) {
    return `Re-create this index with "${tenantColumn}" as its leading column, so the same value can exist once per tenant.${tail}`;
  }
  return (
    `Scope the index to the tenant so the same value can exist once per tenant. ` +
    `No constraint of this name exists — it was created as a bare index, so there is nothing to ALTER:\n` +
    `        DROP INDEX ${qualified(r.schema, r.index)};\n` +
    `        ${create};` +
    tail
  );
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

  // Per-table { column: type } and { column: default } — used to reason about
  // expression indexes and to spot random-generator defaults.
  const cf = columnFactsSql(cfg.schemas);
  const typesOf = new Map();
  const defaultsOf = new Map();
  for (const r of await q(cf.text, cf.values)) {
    const id = `${r.schema}.${r.table}`;
    if (!typesOf.has(id)) { typesOf.set(id, {}); defaultsOf.set(id, {}); }
    typesOf.get(id)[r.column] = r.type;
    defaultsOf.get(id)[r.column] = r.default_expr;
  }

  const violations = [];
  const notes = [];
  const unanalysed = [];
  const secrets = [];
  let scanned = 0;

  // ── unique/exclusion oracles (a build failure) ─────────────────────
  const ui = uniqueIndexSql(cfg.schemas);
  for (const r of await q(ui.text, ui.values)) {
    const id = `${r.schema}.${r.table}`;
    if (skip.has(id) || skip.has(`${r.schema}.${r.index}`) || skip.has(r.index)) continue;
    const tenantColumn = tenantOf.get(id);
    const isExclusion = r.is_exclusion === true || r.is_exclusion === 't';
    const verdict = classifyUniqueIndex({
      isPrimary: r.is_primary === true || r.is_primary === 't',
      hasExpression: r.has_expression === true || r.has_expression === 't',
      columns: r.columns || [],
      types: r.types || [],
      expr: r.expr ?? null,
      tenantColumn,
      unguessableTypes: cfg.unguessableTypes,
      columnTypes: typesOf.get(id) || null,
      columnDefaults: defaultsOf.get(id) || null,
    });
    if (verdict.status === 'skip') continue;
    scanned++; // notes count as looked-at too — a skip is not a pass
    if (verdict.status === 'note') {
      const entry = { where: `${id} (${r.index})`, reason: verdict.reason };
      if (verdict.kind === 'global-secret') secrets.push(entry); else unanalysed.push(entry);
      continue;
    }
    if (verdict.status !== 'oracle') continue;
    const cols = (r.columns || []).map((c) => (c == null ? r.expr || '<expression>' : `"${c}"`)).join(', ');
    violations.push({
      where: `${id} (${r.index})`,
      kind: isExclusion ? 'exclusion-oracle' : 'unique-oracle',
      message: isExclusion
        ? `EXCLUDE (${cols}) on a tenant-scoped table does not include "${tenantColumn}", so it is enforced ACROSS every tenant. ` +
          `Exclusion constraints are checked BELOW row-level security, exactly like unique indexes: inserting a row that conflicts with another tenant's raises "conflicting key value violates exclusion constraint" even though RLS hides the row that caused it. ` +
          `With WITH = that is a unique key by another name; with an overlap operator it answers "is that resource taken at that time" for tenants you cannot see`
        : `UNIQUE ${cols} on a tenant-scoped table does not include "${tenantColumn}", so it is enforced ACROSS every tenant. ` +
          `Unique indexes are checked BELOW row-level security: inserting a value that already exists in another tenant raises "duplicate key value violates unique constraint" even though RLS hides the row that caused it. ` +
          `Anyone who can attempt an insert can therefore test whether a given value (an email, a slug, a phone number) exists in some other tenant — and ON CONFLICT DO NOTHING answers the same question silently, with no error at all`,
      fix: fixFor(r, tenantColumn),
    });
  }

  if (secrets.length > 0) {
    notes.push({
      where: `${secrets.length} global unique key(s) on bearer credentials`,
      message:
        `${secrets.map((s) => s.where).slice(0, 3).join('; ')}${secrets.length > 3 ? `; +${secrets.length - 3} more` : ''} are globally unique and NOT scoped to the tenant. ` +
        `That is reported here rather than failed, and the advice runs the other way: KEEP the global constraint. ` +
        `A bearer credential is looked up with no tenant in hand (\`where token = $1\`), and global uniqueness is what makes that lookup resolve to exactly one tenant — scoping it to "(organization_id, token)" was measured to let the same token exist in two organizations, so a \`.single()\` lookup then resolves one secret to an arbitrary tenant. ` +
        `The residual risk is different: if the value is short or guessable (a join code, a coupon), lengthen it or give the column a random DEFAULT. Do not scope the constraint.`,
    });
  }

  if (unanalysed.length > 0) {
    notes.push({
      where: `${unanalysed.length} constraint(s) not analysed`,
      message:
        `${unanalysed.map((u) => u.where).slice(0, 3).join('; ')}${unanalysed.length > 3 ? `; +${unanalysed.length - 3} more` : ''} are expression indexes whose expression names no column this tool recognises, so no verdict was reached — in either direction. ` +
        `Check by hand whether the indexed expression is derived only from tenant-scoped, unguessable values; if it is derived from a guessable one (an email, a slug), it is a cross-tenant existence oracle and the tenant column belongs in the index.`,
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
        `Listed here as a catalog fact; \`tenant-guard fks\` (cross-tenant-fk) PROVES whether it is reachable, and covers the worse half — with ON DELETE CASCADE the other tenant deleting their own row deletes these rows. ` +
        `The fix is a composite FK that carries the tenant, e.g. FOREIGN KEY (organization_id, parent_id) REFERENCES parent (organization_id, id).`,
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
        : `${scanned} tenant uniqueness constraint(s) checked; none leak across tenants` + (notes.length ? ` (${notes.length} note(s))` : ''),
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
