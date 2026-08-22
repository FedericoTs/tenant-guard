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
 * readable by your app role **and** either RLS is off on it, or RLS is on but
 * every row is returned to that role anyway. If the role can't read it, nothing
 * is exposed.
 *
 * The RLS carve-out used to be blanket — "RLS is on, the other guards judge it".
 * Measured: that hand-off is empty exactly where this guard matters. With
 * `audit_log(id, actor, detail)` (no tenant column), `enable row level security`
 * and `create policy audit_read for select using (true)`, tenant A read BOTH
 * tenants' rows while all 22 guards reported green — rls-proof never plans the
 * table because `introspectionSql` joins `pg_attribute` on the tenant column,
 * and anon-reads/column-exposure probe `anon`, not the app role. So the
 * carve-out is now narrowed to `RLS on AND a tenant column exists`, which is
 * precisely the case rls-proof does plan.
 */
import {
  qualified,
  quoteIdent,
  safeRole,
  introspectionSql,
  planTables,
  tenantComparison,
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

/**
 * RLS status, tenant column (and its type), the app role's SELECT grant, and
 * what the role's SELECT policies actually do, for a set of tables.
 *
 * The tenant column's TYPE is carried because the emitted policy has to compile:
 * `USING ("org_id" = current_setting('app.current_tenant'))` raises 42883
 * `operator does not exist: uuid = text` on a uuid column — the commonest tenant
 * type there is. Measured on the shape this guard reports most: uuid uncast
 * FAILED 42883, uuid with `::uuid` on the setting OK, bigint uncast FAILED
 * 42883, bigint with `::text` on the column OK. `tenantComparison()` picks.
 *
 * The policy counts answer one question, from the catalog, without probing:
 * "for THIS role, on SELECT, is RLS decorative?" A policy applies to the role
 * when `polroles` contains PUBLIC (oid 0) or a role the app role is a member of;
 * it governs reads when `polcmd` is 'r' (SELECT) or '*' (ALL). Decorative means
 * a PERMISSIVE applicable policy whose qual is the constant `true` AND no
 * RESTRICTIVE applicable policy to narrow it — that combination returns every
 * row, conclusively. Measured against the three shapes that look alike:
 *   using (true)                             -> all_rows ['wide'], restrictive 0  (leak)
 *   using (true) TO reporter + scoped TO app -> all_rows null                     (correct code)
 *   using (true) + AS RESTRICTIVE tenant pol -> all_rows ['wide'], restrictive 1  (correct code)
 * the last two both let `authenticated` see 1 of 2 rows, so neither may fire.
 */
export function destinationSql(qualifiedNames, tenantColumns, role) {
  // "this policy has a say in what $3 sees when it reads this table"
  const applies = `(
             0 = any(p.polroles)
             or exists (select 1 from unnest(p.polroles) r
                         where pg_catalog.pg_has_role($3::text, r, 'USAGE'))
           )`;
  const text = `
    select n.nspname as schema,
           c.relname as table,
           c.relrowsecurity as rls_enabled,
           pg_catalog.has_table_privilege($3::text, c.oid, 'SELECT') as can_select,
           (select a.attname
              from pg_catalog.pg_attribute a
             where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
               and a.attname = any($2)
             limit 1) as tenant_column,
           (select pg_catalog.format_type(a.atttypid, a.atttypmod)
              from pg_catalog.pg_attribute a
             where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
               and a.attname = any($2)
             limit 1) as tenant_type,
           (select count(*) from pg_catalog.pg_policy p
             where p.polrelid = c.oid and p.polpermissive
               and p.polcmd in ('r', '*') and ${applies})::int as permissive_count,
           (select count(*) from pg_catalog.pg_policy p
             where p.polrelid = c.oid and not p.polpermissive
               and p.polcmd in ('r', '*') and ${applies})::int as restrictive_count,
           (select array_agg(p.polname) from pg_catalog.pg_policy p
             where p.polrelid = c.oid and p.polpermissive
               and p.polcmd in ('r', '*') and ${applies}
               and pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'true') as all_rows_policies
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where (n.nspname || '.' || c.relname) = any($1)
      and c.relkind in ('r', 'p')`;
  return { text, values: [qualifiedNames, tenantColumns, role] };
}

/**
 * Blank out SQL comments in a plpgsql body, leaving everything else byte-aligned.
 *
 * Needed because the write scan below is regex over raw text: a table named only
 * inside a comment was reported as a write destination, and the message asserts
 * as fact that the table "receives rows derived from tenant data". Measured on
 * the naive shapes, all of which returned a destination before this existed:
 *   `-- 2023: we used to "insert into app_settings" here; removed, it leaked`
 *   `/ * old: insert into audit_log(a) values (1); * /`
 *
 * It has to be a lexer, not a blanket `replace` of everything after a `--`.
 * Measured: on
 * `raise notice 'skipped -- see ticket'; insert into audit_log(a) values (1);`
 * the naive strip eats the rest of the line and loses a REAL write (returns []),
 * where this pass returns ["public.audit_log"]. So single-quoted, dollar-quoted
 * and double-quoted spans are tracked and skipped whole — and, deliberately,
 * kept in the output: `execute 'insert into audit_log(a) values (1)'` is a
 * genuine write this guard catches today and must keep catching.
 *
 * Comment characters are replaced with spaces rather than deleted so offsets and
 * line breaks survive — a `--` comment can't glue two statements together.
 *
 * Deliberately NOT `stripSqlComments` from definer-grants.mjs, and named
 * differently so the two are not confused: that one is the naive two-`replace`
 * version. It is fine for its own input (migration files) but would lose the
 * `raise notice` write above, and three other guards depend on it, so it is left
 * alone rather than widened from here.
 */
export function blankSqlComments(sql) {
  const s = String(sql || '');
  const out = s.split('');
  const n = s.length;
  const blank = (from, to) => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  let i = 0;
  while (i < n) {
    const c = s[i];
    // $tag$ … $tag$ — plpgsql nests these for dynamic SQL. Skipped whole.
    if (c === '$') {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(s.slice(i));
      if (m) {
        const end = s.indexOf(m[0], i + m[0].length);
        i = end === -1 ? n : end + m[0].length;
        continue;
      }
    }
    if (c === "'") {
      // E'…' honours backslash escapes; a plain literal only doubles the quote.
      const prev = s[i - 1] ?? '';
      const prev2 = s[i - 2] ?? ' ';
      const escapes = /[eE]/.test(prev) && !/[A-Za-z0-9_$]/.test(prev2);
      i++;
      while (i < n) {
        if (escapes && s[i] === '\\') { i += 2; continue; }
        if (s[i] === "'") {
          if (s[i + 1] === "'") { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (c === '"') {
      i++;
      while (i < n) {
        if (s[i] === '"') {
          if (s[i + 1] === '"') { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (c === '-' && s[i + 1] === '-') {
      let j = s.indexOf('\n', i);
      if (j === -1) j = n;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === '/' && s[i + 1] === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (s[j] === '/' && s[j + 1] === '*') { depth++; j += 2; continue; }
        if (s[j] === '*' && s[j + 1] === '/') { depth--; j += 2; continue; }
        j++;
      }
      blank(i, j);
      i = j;
      continue;
    }
    i++;
  }
  return out.join('');
}

/**
 * Tables a trigger function writes to, read out of its body.
 *
 * plpgsql bodies are opaque to the catalog, so this is text analysis — and it is
 * deliberately literal: an `INSERT INTO`/`UPDATE`/`MERGE INTO` naming a table
 * directly. A dynamically-assembled target is not found, which is stated as a
 * limitation rather than papered over.
 *
 * The UPDATE pattern tolerates `ONLY` and an optional `[AS] alias`, because
 * `\s+set\b` welded to the table name made the verdict depend on the alias, not
 * on the leak. Measured on two databases identical but for the trigger body:
 * `update tenant_rollup set …` -> ok=false "1 unprotected table(s)"; `update
 * tenant_rollup r set …` -> ok=true "no triggers … write to an unguarded
 * destination". Both leaked the same rows to the wrong tenant. The alias group
 * is optional, so everything the old pattern matched still matches; checked that
 * `on conflict (id) do update set n = excluded.n` and `select … for update`
 * still yield [] (the alias group backtracks and the required `set` never
 * arrives).
 */
export function writeTargets(body, defaultSchema = 'public') {
  const s = blankSqlComments(body);
  const out = new Set();
  const add = (schema, table) => {
    if (!table) return;
    const t = table.replace(/"/g, '').toLowerCase();
    // NEW/OLD are trigger records, not tables.
    if (['new', 'old'].includes(t)) return;
    out.add(`${(schema || defaultSchema).replace(/"/g, '').toLowerCase()}.${t}`);
  };
  for (const m of s.matchAll(/\binsert\s+into\s+(?:("?[\w$]+"?)\s*\.\s*)?("?[\w$]+"?)/gi)) add(m[1], m[2]);
  for (const m of s.matchAll(/\bupdate\s+(?:only\s+)?(?:("?[\w$]+"?)\s*\.\s*)?("?[\w$]+"?)(?:\s+(?:as\s+)?"?[\w$]+"?)?\s+set\b/gi)) add(m[1], m[2]);
  for (const m of s.matchAll(/\bmerge\s+into\s+(?:only\s+)?(?:("?[\w$]+"?)\s*\.\s*)?("?[\w$]+"?)/gi)) add(m[1], m[2]);
  return [...out];
}

/**
 * The remediation, written so that pasting it does not break the SOURCE table.
 *
 * Measured, applying the previous version of this advice verbatim: the three
 * statements applied cleanly, and the very next `insert into invoices` — the
 * protected table the trigger hangs off — failed with 42501 "new row violates
 * row-level security policy for table \"audit_log\"", while the guard flipped to
 * ok=true. Two things caused it and both are now part of the recipe:
 *   1. nothing populated the new column, so the trigger's row had NULL in it;
 *   2. a PERMISSIVE policy with only USING supplies the WITH CHECK for INSERT,
 *      so the AFTER trigger's write is judged by the read predicate.
 * WITH CHECK is written out explicitly rather than left implicit, but the
 * load-bearing step is (1) — and `WITH CHECK (true)` is NOT offered, because
 * that trades the broken write for a write leak. Rows left NULL after the switch
 * are invisible to every tenant, so the backfill is spelled out too: measured,
 * reading the destination as the tenant afterwards returned 0 rows.
 */
function remediation({ schema, table, tenantColumn, tenantColumnType, role, sources, sourceTenantColumn, dropPolicies = [], rlsEnabled = false }) {
  const dest = qualified(schema, table);
  const col = tenantColumn || 'organization_id';
  const type = tenantColumn ? tenantColumnType : 'text';
  const cmp = tenantComparison(quoteIdent(col), type);
  const src = sources[0] || 'the source table';
  const srcCol = quoteIdent(sourceTenantColumn || col);
  const drops = dropPolicies.map((p) => `        DROP POLICY ${quoteIdent(p)} ON ${dest};\n`).join('');
  return (
    `Protect the destination like the source it copies from — all of it, in this\n` +
    `      order. The policy on its own STOPS writes to ${src}:\n` +
    (tenantColumn
      ? ''
      // `col` here is the synthesized literal `organization_id` — a plain
      // lower-case identifier, so it is emitted unquoted.
      : `        -- 1. give the row a tenant to be scoped by:\n` +
        `        ALTER TABLE ${dest} ADD COLUMN ${col} ${type};\n`) +
    `        -- ${tenantColumn ? '1' : '2'}. make the trigger carry the tenant across:\n` +
    `        --      INSERT INTO ${dest} (${quoteIdent(col)}, ...) VALUES (NEW.${srcCol}, ...);\n` +
    `        --    Until it does, every INSERT INTO ${src} fails with 42501 "new row\n` +
    `        --    violates row-level security policy" — the trigger's write is checked\n` +
    `        --    against the WITH CHECK below.\n` +
    `        -- ${tenantColumn ? '2' : '3'}. backfill, or the rows already there become invisible to EVERY tenant:\n` +
    `        --      UPDATE ${dest} SET ${quoteIdent(col)} = <owning tenant> WHERE ${quoteIdent(col)} IS NULL;\n` +
    `        -- ${tenantColumn ? '3' : '4'}. then scope it:\n` +
    drops +
    (rlsEnabled ? '' : `        ALTER TABLE ${dest} ENABLE ROW LEVEL SECURITY;\n`) +
    `        CREATE POLICY tenant_isolation ON ${dest}\n` +
    `          USING (${cmp})\n` +
    `          WITH CHECK (${cmp});\n` +
    `      (If ${src} scopes by something other than the app.current_tenant GUC, use\n` +
    `      that same mechanism here — do not copy its policy expression verbatim, it\n` +
    `      refers to its own columns.)\n` +
    `      Or, if it is meant to be operator-only: REVOKE SELECT ON ${dest} FROM ${role};`
  );
}

/**
 * Verdict for one destination table.
 *
 * 'note' is a real outcome here, not a soft failure: RLS is on, there is no
 * tenant column, and the applicable policies scope by something this guard
 * cannot read (a GUC flag, a membership join). Nothing downstream will look at
 * the table either, so saying "I could not judge this" is the honest answer —
 * reporting green would be a skip dressed up as a pass.
 *
 * @returns {{status:'leak'|'safe'|'note', message?:string, fix?:string}}
 */
export function classifyDestination({
  schema,
  table,
  rlsEnabled,
  canSelect,
  tenantColumn,
  tenantColumnType = null,
  permissiveCount = 0,
  restrictiveCount = 0,
  allRowsPolicies = [],
  sources = [],
  sourceTenantColumn = null,
  role = 'authenticated',
}) {
  if (!canSelect) return { status: 'safe' };   // the role can't read it — nothing exposed
  // RLS on AND a tenant column: rls-proof's introspectionSql joins pg_attribute
  // on the tenant column, so it plans exactly this table and judges it on its
  // merits. That is the one case where the hand-off is real.
  if (rlsEnabled && tenantColumn) return { status: 'safe' };

  const via = sources.join(', ');
  const decorative = rlsEnabled && allRowsPolicies.length > 0 && restrictiveCount === 0;

  if (rlsEnabled && !decorative) {
    // RLS on, no applicable permissive SELECT policy => Postgres denies every row
    // to this role. Nothing is exposed; stay silent.
    if (permissiveCount === 0) return { status: 'safe' };
    return {
      status: 'note',
      message:
        `${schema}.${table} receives rows derived from tenant data (written by a trigger on ${via}) and has RLS enabled, but no tenant column — so no tenant-column check in this tool will ever plan it. Its ${permissiveCount} SELECT polic${permissiveCount === 1 ? 'y' : 'ies'} for "${role}" scope by something other than a tenant column, which cannot be judged from the catalog. Confirm by hand that "${role}" cannot read another tenant's rows here`,
    };
  }

  const message = decorative
    ? `${schema}.${table} receives rows derived from tenant data (written by a trigger on ${via}), "${role}" can read it, and although RLS is enabled the policy ${allRowsPolicies.map((p) => `"${p}"`).join(', ')} is PERMISSIVE with a constant-true qual and nothing RESTRICTIVE narrows it — so every row is returned to "${role}" anyway. There is no tenant column here either, so no other check in this tool plans this table: RLS being "on" is the only thing that looks protective about it`
    : `${schema}.${table} receives rows derived from tenant data (written by a trigger on ${via}), "${role}" can read it, and it has NO row-level security` +
      (tenantColumn ? ` — despite carrying a "${tenantColumn}" column that could scope it` : ` and no tenant column to scope it by`) +
      `. The data left a protected table and nothing followed it: every tenant's activity is readable here by any logged-in user, and the tenant-column guards walk past it because there is nothing to key on`;

  return {
    status: 'leak',
    message,
    fix: remediation({
      schema,
      table,
      tenantColumn,
      tenantColumnType,
      role,
      sources,
      sourceTenantColumn,
      dropPolicies: decorative ? allRowsPolicies : [],
      rlsEnabled: !!rlsEnabled,
    }),
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
  // Keep each source's tenant column: the fix has to tell the user which value
  // the trigger must carry into the destination (`NEW."organization_id"`), and
  // that is the source's column, not the destination's.
  const sourcePlan = planTables(await q(intro.text, intro.values), cfg.tenantColumns);
  const sourceTenantColumns = new Map(sourcePlan.map((t) => [`${t.schema}.${t.table}`, t.tenantColumn]));
  const tenantTables = new Set(sourceTenantColumns.keys());
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
  let unjudged = 0;

  for (const r of rows) {
    const id = `${r.schema}.${r.table}`;
    scanned++;
    const sources = [...(feeds.get(id) || [])];
    const verdict = classifyDestination({
      schema: r.schema,
      table: r.table,
      rlsEnabled: r.rls_enabled === true || r.rls_enabled === 't',
      canSelect: r.can_select === true || r.can_select === 't',
      tenantColumn: r.tenant_column,
      tenantColumnType: r.tenant_type ?? null,
      permissiveCount: Number(r.permissive_count ?? 0),
      restrictiveCount: Number(r.restrictive_count ?? 0),
      allRowsPolicies: r.all_rows_policies ?? [],
      sources,
      sourceTenantColumn: sourceTenantColumns.get(sources[0]) ?? null,
      role,
    });
    if (verdict.status === 'leak') {
      violations.push({ where: id, kind: 'shadow', message: verdict.message, fix: verdict.fix });
    } else if (verdict.status === 'note') {
      notes.push({ where: id, message: verdict.message });
      unjudged++;
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
        // Don't claim "all protected" when some destination could only be noted.
        // A skip is not a pass; say how many were actually decided.
        : unjudged > 0
          ? `${scanned} trigger destination(s) checked; ${unjudged} could not be judged from the catalog (see notes)`
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
