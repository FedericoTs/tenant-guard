/**
 * Guard: runtime RLS isolation proof — the tripwire becomes a proof.
 *
 * The three static guards read source text; they catch the obvious leak but
 * cannot *prove* that isolation holds. This one can. Given a database
 * connection it:
 *
 *   1. introspects every table in your schema that carries a tenant column
 *      (organization_id / tenant_id / …), noting whether RLS is even on;
 *   2. as the PRIVILEGED role (which bypasses RLS, like Supabase `service_role`)
 *      finds two real tenant ids that already have data in each table;
 *   3. drops to your non-superuser APP role (e.g. `authenticated`), assumes the
 *      identity of tenant A, and asserts A's session sees **zero** of tenant B's
 *      rows — then swaps and checks the other direction.
 *
 * A static scanner can never do this. A test can: if RLS is off, or a policy is
 * `USING (true)`, or a policy forgot the tenant predicate, tenant A's session
 * sees tenant B's rows and this guard fails your build — on every commit.
 *
 * Everything runs inside a single transaction that is ROLLED BACK, and the
 * guard only ever SELECTs, so it is non-destructive by construction. It needs a
 * Postgres driver (`pg`, an optional peer dependency) and a database URL; with
 * neither it SKIPS, exactly like the other guards on a stack they don't fit.
 *
 * The pure helpers below are I/O-free and unit-tested with zero dependencies;
 * `prove()` takes an injected `query` function so it can be driven by `pg` in
 * production and by an embedded Postgres in tests.
 */

export const meta = {
  id: 'rls-proof',
  title: 'Runtime RLS isolation proof',
  why: "Proves at runtime that a tenant's session cannot read another tenant's rows — catches RLS that is off, permissive, or missing the tenant predicate, which no source scan can prove.",
};

// ── configuration defaults ───────────────────────────────────────────
export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: ['organization_id', 'organizationId', 'tenant_id', 'tenantId', 'account_id', 'workspace_id', 'org_id'],
  // The non-superuser role your app queries as. RLS applies to it; it bypasses
  // for the privileged connecting role. Supabase: 'authenticated'.
  role: 'authenticated',
  // SQL run (as `role`) to assume a tenant's identity. `$1` is the tenant id.
  // The default targets the canonical Postgres pattern:
  //   ... USING (tenant_col = current_setting('app.current_tenant'))
  // For Supabase JWT-claim policies, override with e.g.
  //   ["select set_config('request.jwt.claims', json_build_object('sub',$1,'org_id',$1)::text, true)"]
  becomeTenant: ["select set_config('app.current_tenant', $1, true)"],
  tables: null, // null = autodiscover; or [{ table, schema?, tenantColumn }]
  grandfather: [], // table names deliberately shared/unscoped (reference data)
  sampleLimit: 3, // distinct tenant ids to sample per table
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Safely double-quote a Postgres identifier. Rejects embedded NULs. */
export function quoteIdent(name) {
  if (typeof name !== 'string' || name.length === 0 || name.includes('\0')) {
    throw new Error(`unsafe identifier: ${JSON.stringify(name)}`);
  }
  return '"' + name.replace(/"/g, '""') + '"';
}

/** `schema.table`, each part quoted. */
export function qualified(schema, table) {
  return `${quoteIdent(schema)}.${quoteIdent(table)}`;
}

/** Validate a role name for interpolation into SET ROLE (no params allowed there). */
export function safeRole(role) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)) {
    throw new Error(`unsafe role name: ${JSON.stringify(role)}`);
  }
  return role;
}

/**
 * Catalog query: every table in `schemas` that has any of `tenantColumns`,
 * with whether RLS is enabled/forced. Uses pg_catalog so it also reports RLS
 * status (information_schema can't). Returns { text, values }.
 */
export function introspectionSql(schemas, tenantColumns) {
  const text = `
    select n.nspname            as schema,
           c.relname            as table,
           a.attname            as column,
           c.relrowsecurity     as rls_enabled,
           c.relforcerowsecurity as rls_forced
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    where c.relkind = 'r'
      and n.nspname = any($1)
      and a.attname = any($2)
    order by n.nspname, c.relname`;
  return { text, values: [schemas, tenantColumns] };
}

/**
 * From the introspection rows, one entry per table: the tenant column chosen by
 * the priority order in `tenantColumns`, plus rls flags. Grandfathered tables
 * are dropped.
 */
export function planTables(rows, tenantColumns, grandfather = []) {
  const skip = new Set(grandfather);
  const byTable = new Map();
  for (const r of rows) {
    const key = `${r.schema}.${r.table}`;
    if (skip.has(r.table) || skip.has(key)) continue;
    const prio = tenantColumns.indexOf(r.column);
    if (prio < 0) continue;
    const existing = byTable.get(key);
    if (!existing || prio < existing.prio) {
      byTable.set(key, {
        schema: r.schema,
        table: r.table,
        tenantColumn: r.column,
        rlsEnabled: r.rls_enabled === true || r.rls_enabled === 't',
        rlsForced: r.rls_forced === true || r.rls_forced === 't',
        prio,
      });
    }
  }
  return [...byTable.values()].map(({ prio, ...t }) => t);
}

/** Privileged query for the distinct tenant ids present in a table (as text). */
export function distinctTenantsSql(schema, table, column, limit) {
  const text =
    `select distinct ${quoteIdent(column)}::text as t ` +
    `from ${qualified(schema, table)} ` +
    `where ${quoteIdent(column)} is not null ` +
    `limit $1`;
  return { text, values: [limit] };
}

/** Restricted-role count of rows belonging to `tenantId` (compared as text). */
export function tenantRowCountSql(schema, table, column, tenantId) {
  const text =
    `select count(*)::int as n ` +
    `from ${qualified(schema, table)} ` +
    `where ${quoteIdent(column)}::text = $1`;
  return { text, values: [tenantId] };
}

/** Expand the becomeTenant templates into { text, values } for a tenant id. */
export function buildBecomeTenant(templates, tenantId) {
  return templates.map((text) => ({ text, values: [tenantId] }));
}

/** Is a caught error a Postgres "permission denied" (42501)? Then the role simply can't read — safe. */
export function isPermissionDenied(err) {
  if (!err) return false;
  if (err.code === '42501') return true;
  return /permission denied/i.test(err.message || '');
}

/**
 * Turn one table's measurements into a verdict.
 * @returns {{ status: 'isolated'|'leak'|'insufficient-data'|'over-restrictive'|'no-access', message: string, fix?: string }}
 */
export function classifyTableResult({ rlsEnabled, ownVisible, crossVisible, tenantCount, noAccess }) {
  if (noAccess) {
    return {
      status: 'no-access',
      message: `role cannot read this table at all (no SELECT grant) — nothing to prove`,
    };
  }
  if (tenantCount < 2) {
    return {
      status: 'insufficient-data',
      message: `only ${tenantCount} tenant(s) of data present — cannot prove cross-tenant isolation until two tenants exist`,
    };
  }
  if (crossVisible > 0) {
    const cause = rlsEnabled
      ? `a policy is permissive or missing the tenant predicate`
      : `ROW LEVEL SECURITY is not enabled on this table`;
    return {
      status: 'leak',
      message: `tenant A's session read ${crossVisible} row(s) belonging to tenant B — ${cause}`,
      fix: rlsEnabled
        ? `Fix the policy so it scopes by the tenant column, e.g. USING (${'{col}'} = current_setting('app.current_tenant')). Re-run: it must show 0 cross-tenant rows.`
        : `Enable + force RLS and add a tenant policy:\n  ALTER TABLE ${'{tbl}'} ENABLE ROW LEVEL SECURITY;\n  ALTER TABLE ${'{tbl}'} FORCE ROW LEVEL SECURITY;\n  CREATE POLICY tenant_isolation ON ${'{tbl}'} USING (${'{col}'} = current_setting('app.current_tenant'));`,
    };
  }
  if (ownVisible === 0) {
    return {
      status: 'over-restrictive',
      message: `the tenant session sees none of its own rows either — likely the role/becomeTenant config doesn't match your policies (not a leak, but this table wasn't actually proven)`,
    };
  }
  return { status: 'isolated', message: `isolated — tenant session sees its own rows and zero of the other tenant's` };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

/**
 * Run the proof against an injected query function.
 * @param {(text:string, values?:any[]) => Promise<{rows:any[]}>} query
 * @param {object} config  see DEFAULTS
 */
export async function prove({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const role = safeRole(cfg.role);
  const violations = [];
  const notes = [];
  let scanned = 0;
  let provenCount = 0;

  const q = async (text, values) => (await query(text, values)).rows;

  // Discover the tables to probe (either configured or introspected).
  let plan;
  if (Array.isArray(cfg.tables) && cfg.tables.length) {
    plan = cfg.tables
      .filter((t) => !cfg.grandfather.includes(t.table))
      .map((t) => ({ schema: t.schema ?? cfg.schemas[0] ?? 'public', table: t.table, tenantColumn: t.tenantColumn, rlsEnabled: undefined }));
  } else {
    const introspect = introspectionSql(cfg.schemas, cfg.tenantColumns);
    const rows = await q(introspect.text, introspect.values);
    plan = planTables(rows, cfg.tenantColumns, cfg.grandfather);
  }

  if (plan.length === 0) {
    return OK({
      skipped: true,
      reason: `no tables with a tenant column (${cfg.tenantColumns.join(', ')}) found in ${cfg.schemas.join(', ')}`,
      summary: 'skipped — nothing to prove',
    });
  }

  await query('begin', []);
  try {
    // Pass 1 — PRIVILEGED: sample the tenant ids present in each table.
    for (const t of plan) {
      try {
        const d = distinctTenantsSql(t.schema, t.table, t.tenantColumn, cfg.sampleLimit);
        t.tenants = (await q(d.text, d.values)).map((r) => r.t);
      } catch (err) {
        t.introspectError = err.message;
        t.tenants = [];
      }
    }

    // Pass 2 — RESTRICTED: assume the app role and prove isolation per table.
    await query(`set local role ${role}`, []);
    for (const t of plan) {
      if (t.introspectError) {
        notes.push({ where: `${t.schema}.${t.table}`, message: `could not sample tenants: ${t.introspectError}` });
        continue;
      }
      if (t.tenants.length < 2) {
        scanned++;
        const verdict = classifyTableResult({ rlsEnabled: t.rlsEnabled, tenantCount: t.tenants.length, ownVisible: 0, crossVisible: 0 });
        notes.push({ where: `${t.schema}.${t.table}`, message: verdict.message });
        continue;
      }
      const [tenantA, tenantB] = t.tenants;
      scanned++;

      let noAccess = false;
      let ownVisible = 0;
      let crossVisible = 0;
      try {
        // become tenant A, look for tenant B's rows (and confirm A sees its own)
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantA)) await query(s.text, s.values);
        const own = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantA);
        const cross = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantB);
        ownVisible = (await q(own.text, own.values))[0].n;
        crossVisible = (await q(cross.text, cross.values))[0].n;

        // reverse direction: become tenant B, look for tenant A's rows
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantB)) await query(s.text, s.values);
        const crossRev = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantA);
        crossVisible = Math.max(crossVisible, (await q(crossRev.text, crossRev.values))[0].n);
      } catch (err) {
        if (isPermissionDenied(err)) noAccess = true;
        else throw err;
      }

      const verdict = classifyTableResult({ rlsEnabled: t.rlsEnabled, ownVisible, crossVisible, tenantCount: t.tenants.length, noAccess });
      const tbl = qualified(t.schema, t.table);
      if (verdict.status === 'leak') {
        violations.push({
          where: `${t.schema}.${t.table} (${t.tenantColumn})`,
          message: verdict.message,
          fix: (verdict.fix || '').split('{col}').join(quoteIdent(t.tenantColumn)).split('{tbl}').join(tbl),
          crossVisible,
          rlsEnabled: t.rlsEnabled,
        });
      } else if (verdict.status === 'isolated') {
        provenCount++;
      } else {
        notes.push({ where: `${t.schema}.${t.table}`, message: verdict.message });
      }
    }
  } finally {
    // Non-destructive by construction: nothing is committed.
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  const proven = provenCount;
  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length === 0
        ? `${Math.max(proven, 0)}/${scanned} tenant table(s) proven isolated` + (notes.length ? `; ${notes.length} not proven (see notes)` : '')
        : `${violations.length} table(s) leak across tenants`,
  };
}

/**
 * CLI/programmatic entry: resolve a Postgres connection from the environment,
 * dynamically import `pg`, and run the proof. SKIPS cleanly (never fails the
 * build) when no database URL is configured or `pg` isn't installed — a skip is
 * not a pass, and the CLI says so.
 *
 * @param {object} config  see DEFAULTS, plus optional `url`
 */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) {
    return OK({
      skipped: true,
      reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL) to a test/staging database to run the proof`,
      summary: 'skipped — no database',
    });
  }

  let pg;
  try {
    pg = await import('pg');
  } catch {
    return OK({
      skipped: true,
      reason: `Postgres driver not installed — run \`npm i -D pg\` to enable the runtime RLS proof`,
      summary: 'skipped — pg not installed',
    });
  }

  const Client = pg.default?.Client ?? pg.Client;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    const query = (text, values) => client.query(text, values);
    return await prove({ query, config: cfg });
  } finally {
    await client.end();
  }
}
