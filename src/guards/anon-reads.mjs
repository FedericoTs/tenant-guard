/**
 * Guard: the unauthenticated READ surface. Which tenant tables can `anon` — a
 * visitor with the public key, no login — SELECT?
 *
 * This is the CVE-2025-48757 class in its purest form: the public anon key ships
 * in every browser bundle, so if `anon` can read a table that holds tenants' data,
 * anyone can read every tenant's data with no login at all. (303 endpoints across
 * 170 Lovable projects were readable this way.) `rls-proof` proves one *logged-in*
 * tenant can't read another; this proves the *anonymous* public can't read any.
 *
 * It is deliberately scoped to TENANT tables (those with a tenant column) so it
 * doesn't false-flag the many tables that are meant to be public (published
 * content, reference data). Reliability, hybrid like `anon-writes`:
 *   • RLS OFF + `anon` holds a SELECT grant → anon reads every row, structurally,
 *     no policy to gate it. Flagged from the catalog (true even if empty today).
 *   • RLS ON  → we drop to `anon` and actually SELECT: any row returned means the
 *     real policy let `anon` read tenants' rows. An empty table can't be probed —
 *     reported as *not proven*, never as passing.
 *
 * Same negative control as `rls-proof`/`anon-writes`: `anon` must NOT be able to
 * read a deny-all table; if it can, it bypasses RLS and every result is
 * meaningless, so we abort. Non-destructive: one rolled-back, read-only
 * transaction. Needs `pg` + a database URL; skips cleanly without them.
 */
import {
  quoteIdent,
  qualified,
  safeRole,
  introspectionSql,
  planTables,
  DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';
import { viewIntrospectionSql, planViews, fixForView } from './view-isolation.mjs';

export const meta = {
  id: 'anon-reads',
  title: 'Unauthenticated (anon) read surface',
  why: 'Proves the anonymous role cannot SELECT tenant tables — the CVE-2025-48757 class where the public anon key reads every tenant\'s data with no login. Scoped to tables with a tenant column so public content is not flagged.',
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  role: 'anon', // the unauthenticated role to test
  grandfather: [], // tenant-column tables that are intentionally shared/reference data
  allowlist: [], // "schema.table" (or bare table) intentionally readable by anon
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Does the tested role exist? Returns { text, values }. */
export function roleExistsSql(role) {
  return { text: `select 1 from pg_catalog.pg_roles where rolname = $1`, values: [role] };
}

/** Whether `role` holds a SELECT grant on a table, plus its total row count seen
 *  by the PRIVILEGED connection (to tell "anon sees none of N" from "empty"). */
export function readSurfaceSql(schema, table, role) {
  return {
    text:
      `select has_table_privilege($1, format('%I.%I', $2::text, $3::text), 'SELECT') as can_select, ` +
      `(select count(*)::int from ${qualified(schema, table)}) as total`,
    values: [role, schema, table],
  };
}

/** Restricted-role probe: how many rows can `anon` actually SELECT. No WHERE. */
export function anonSelectCountSql(schema, table) {
  return { text: `select count(*)::int as n from ${qualified(schema, table)}`, values: [] };
}

/**
 * Verdict for one tenant table, view, or materialized view.
 *
 * NOTE the asymmetry, which matters: for a base TABLE, "RLS off + SELECT grant"
 * is a structural leak — no policy exists to gate it, so it's true even when the
 * table is empty. For a VIEW or MATERIALIZED VIEW that shortcut is WRONG: views
 * always report `relrowsecurity = false` (RLS is not a thing you enable on them),
 * so applying it would false-flag a perfectly-safe `security_invoker` view over an
 * RLS'd table. Views are therefore always judged by the PROBE.
 *
 * @returns {{status:'leak'|'safe'|'not-proven', viaRls?:boolean, message?:string}}
 */
export function classifyRead({ kind = 'table', rlsEnabled, canSelect, total, anonVisible, role = 'anon' }) {
  if (!canSelect) return { status: 'safe' }; // no grant at all — nothing exposed, whatever the kind
  if (kind === 'table' && !rlsEnabled) {
    // No RLS: the SELECT grant is the whole story — structural, true even if empty.
    return { status: 'leak', viaRls: false, message: `"${role}" can read this tenant table — RLS is OFF and "${role}" holds a SELECT grant, so every tenant's rows are readable with no login (the CVE-2025-48757 class)` };
  }
  if (anonVisible > 0) {
    const why =
      kind === 'matview'
        ? `row-level security NEVER applies to a materialized view, so this snapshot of every tenant is readable with no login`
        : kind === 'view'
          ? `the view exposes tenant rows to an unauthenticated caller (it runs with its owner's rights unless security_invoker is set)`
          : `a policy permits unauthenticated reads`;
    return { status: 'leak', viaRls: true, message: `"${role}" can read ${anonVisible} row(s) through this ${KIND_LABEL[kind]} — ${why} (proven by probe)` };
  }
  if (total === 0) {
    return { status: 'not-proven', message: `${KIND_LABEL[kind].toLowerCase()} is empty — could not prove whether "${role}" can read it; seed a row or add it to the check's data` };
  }
  return { status: 'safe' };
}

const KIND_LABEL = { table: 'tenant table', view: 'VIEW', matview: 'MATERIALIZED VIEW' };

/** Build a violation for a flagged table / view / materialized view. */
export function violationForRead(id, schema, table, role, viaRls, opts = {}) {
  const { kind = 'table', securityInvoker = false, pgVersionNum = null } = opts;
  const base =
    `Unauthenticated reads of tenant data are the CVE class this tool exists to stop. ` +
    (kind === 'table'
      ? `Enable RLS with a tenant policy, or REVOKE SELECT ON ${qualified(schema, table)} FROM ${role};`
      : fixForView({ kind, schema, view: table, securityInvoker, role, pgVersionNum }));
  return {
    where: id,
    kind,
    message:
      `the "${role}" role can SELECT this ${KIND_LABEL[kind]} ` +
      (!viaRls
        ? `(RLS is OFF, so its SELECT grant is unguarded)`
        : kind === 'matview'
          ? `(RLS never applies to a materialized view — proven by probe)`
          : kind === 'view'
            ? `(the view exposes it to an unauthenticated caller — proven by probe)`
            : `(a policy permits it — proven by probe)`),
    fix:
      `${base}\n` +
      `      If this ${kind === 'table' ? 'table' : 'view'} is intentionally public (reference data, published content), add "${id}" to anonReads.allowlist[] or grandfather[].`,
  };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

/**
 * @param {(text:string, values?:any[]) => Promise<{rows:any[]}>} query
 * @param {object} config  see DEFAULTS
 */
export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;

  if ((await q(roleExistsSql(role).text, [role])).length === 0) {
    return OK({ skipped: true, reason: `role "${role}" does not exist — set anonReads.role to your unauthenticated role`, summary: `skipped — no "${role}" role` });
  }

  // Everything with a tenant column that anon might read: base tables, views, and
  // materialized views. A matview of every tenant, auto-granted to anon and
  // auto-exposed by PostgREST, is this CVE class at its worst — and it is
  // invisible to a base-table-only scan.
  const intro = introspectionSql(cfg.schemas, cfg.tenantColumns);
  const tablePlan = planTables(await q(intro.text, intro.values), cfg.tenantColumns, cfg.grandfather)
    .map((t) => ({ ...t, kind: 'table', name: t.table }));
  const vintro = viewIntrospectionSql(cfg.schemas, cfg.tenantColumns);
  const viewPlan = planViews(await q(vintro.text, vintro.values), cfg.tenantColumns, cfg.grandfather)
    .map((v) => ({ ...v, name: v.view, rlsEnabled: false }));
  const skip = new Set(cfg.allowlist);
  const tables = [...tablePlan, ...viewPlan].filter((t) => !skip.has(`${t.schema}.${t.name}`) && !skip.has(t.name));
  if (tables.length === 0) {
    return OK({ skipped: true, reason: `no tenant-column tables or views in ${cfg.schemas.join(', ')}`, summary: 'skipped — no tenant tables' });
  }
  let pgVersionNum = null;
  try { pgVersionNum = Number((await q(`select current_setting('server_version_num') as v`, []))[0].v); } catch { /* optional */ }

  const violations = [];
  const notes = [];
  let scanned = 0;

  await query('begin', []);
  try {
    // Read the privileged surface (grant + total rows) BEFORE dropping role.
    for (const t of tables) {
      const s = readSurfaceSql(t.schema, t.name, role);
      const row = (await q(s.text, s.values))[0];
      t.canSelect = row.can_select === true || row.can_select === 't';
      t.total = row.total ?? 0;
    }

    // Negative control: `anon` must be subject to RLS.
    let canaryReady = false;
    try {
      await query('create temp table tg_anonread_canary (x int)', []);
      await query('insert into tg_anonread_canary values (1), (2)', []);
      await query('alter table tg_anonread_canary enable row level security', []);
      await query('alter table tg_anonread_canary force row level security', []);
      await query(`grant select on tg_anonread_canary to ${role}`, []);
      canaryReady = true;
    } catch (err) {
      notes.push({ where: '(self-check)', message: `could not set up the RLS self-check canary (${err.message})` });
    }
    await query(`set local role ${role}`, []);
    if (canaryReady) {
      let seen = null;
      try { seen = (await q('select count(*)::int as n from tg_anonread_canary', []))[0].n; } catch { /* denied => enforced */ }
      if (seen !== null && seen > 0) {
        try { await query('rollback', []); } catch { /* ignore */ }
        return {
          id: meta.id, ok: false, notes, scanned: 0,
          violations: [{ where: `role "${role}"`, message: `"${role}" can read a deny-all RLS table — it BYPASSES RLS entirely (a superuser / BYPASSRLS role). That is itself critical, and it makes every probe below meaningless.`, fix: `Ensure "${role}" is a normal non-privileged role. In Supabase, anon must not have BYPASSRLS.` }],
          summary: `"${role}" bypasses RLS — aborting`,
        };
      }
    }

    for (const t of tables) {
      scanned++;
      let anonVisible = 0;
      // Probe whenever anon holds a grant and the structural rule doesn't already
      // settle it. Views ALWAYS get probed (see classifyRead) — their
      // relrowsecurity is meaninglessly false.
      if (t.canSelect && (t.kind !== 'table' || t.rlsEnabled)) {
        await query('savepoint tg_r', []);
        try {
          const c = anonSelectCountSql(t.schema, t.name);
          anonVisible = (await q(c.text, c.values))[0].n;
        } catch { /* denied => 0 */ }
        await query('rollback to savepoint tg_r', []);
        await query('release savepoint tg_r', []);
      }
      const verdict = classifyRead({ kind: t.kind, rlsEnabled: t.rlsEnabled, canSelect: t.canSelect, total: t.total, anonVisible, role });
      const id = `${t.schema}.${t.name}`;
      if (verdict.status === 'leak') {
        violations.push(violationForRead(id, t.schema, t.name, role, verdict.viaRls, { kind: t.kind, securityInvoker: t.securityInvoker, pgVersionNum }));
      } else if (verdict.status === 'not-proven') {
        notes.push({ where: id, message: verdict.message });
      }
    }
  } finally {
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length === 0
        ? `${scanned} tenant table(s) checked; none readable by "${role}"`
        : `${violations.length} tenant table(s) readable by "${role}"`,
  };
}

/**
 * CLI/programmatic entry: resolve a Postgres connection, dynamically import `pg`,
 * run the check. Skips cleanly with no database URL or no `pg`.
 */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) {
    return OK({ skipped: true, reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL)`, summary: 'skipped — no database' });
  }
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
