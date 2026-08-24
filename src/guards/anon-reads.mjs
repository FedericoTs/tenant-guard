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

/**
 * Whether `role` holds a SELECT grant. CATALOG ONLY — it does not touch the
 * relation's heap.
 *
 * It used to carry `(select count(*)::int from <rel>) as total` as well, run once
 * per relation before we drop to `anon`. That number had exactly one consumer,
 * `classifyRead`'s `total === 0` emptiness test, so a full seq scan was paid to
 * answer a yes/no question — and paid even for relations `anon` holds no grant on,
 * where `classifyRead` returns 'safe' at its first line without ever looking at it.
 * Measured under PGlite on a 300k-row table: `count(*)` planned as Aggregate over
 * Seq Scan, 3704 shared buffers, 306 ms; `exists(select 1 ...)` planned as an
 * InitPlan that stops at the first row, 2 buffers, 0.05 ms. Emptiness now lives in
 * `nonEmptySql` and is asked only when the answer can change the verdict.
 *
 * Splitting them also removes a spurious "not examined" note: a materialized view
 * created WITH NO DATA raises 55000 on any read, so the old combined query failed
 * for such a matview even when `anon` had no grant on it — a case the catalog
 * alone settles conclusively (no grant ⇒ safe).
 */
export function readSurfaceSql(schema, table, role) {
  return {
    text:
      `select (has_table_privilege($1, format('%I.%I', $2::text, $3::text), 'SELECT') or has_any_column_privilege($1, format('%I.%I', $2::text, $3::text), 'SELECT')) as can_select, ` +
      `has_table_privilege($1, format('%I.%I', $2::text, $3::text), 'SELECT') as can_select_all`,
    values: [role, schema, table],
  };
}

/**
 * "Does this relation hold at least one row?", asked as the PRIVILEGED role.
 * Its only job is to tell "anon sees none of N rows" (safe) from "the table is
 * empty, so the probe proved nothing" (not-proven). A boolean, never a count —
 * no caller has ever rendered the number.
 */
export function nonEmptySql(schema, table) {
  return { text: `select exists(select 1 from ${qualified(schema, table)}) as nonempty`, values: [] };
}

/**
 * Upper bound on the rows the anon probe counts.
 *
 * The verdict only ever asks `anonVisible > 0`, so counting past the bound buys
 * nothing but a full scan of a relation we have just proven is readable by the
 * unauthenticated internet — i.e. the unbounded form was slowest precisely on the
 * databases that are broken. Measured on 300k rows: unbounded `count(*)` 306 ms /
 * 3704 buffers vs bounded 1.7 ms / 14 buffers. When the bound is hit the message
 * reads "1000+", never a wrong exact number.
 */
export const ANON_PROBE_CAP = 1000;

/**
 * Restricted-role probe: how many rows can `anon` actually SELECT, counted up to
 * `cap + 1`. No WHERE — RLS still applies to the inner scan, so detection is
 * identical to the unbounded form; only the reported magnitude saturates. `cap` is
 * forced to a safe positive integer before interpolation: it is a literal, not a
 * bind parameter, because a LIMIT inside a sub-select cannot take `$n` on every
 * driver path this guard runs under (PGlite's simple-protocol path included).
 */
export function anonSelectCountSql(schema, table, cap = ANON_PROBE_CAP) {
  const n = Number.isSafeInteger(cap) && cap > 0 ? cap : ANON_PROBE_CAP;
  return {
    text: `select count(*)::int as n from (select 1 from ${qualified(schema, table)} limit ${n + 1}) s`,
    values: [],
  };
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
 * `nonempty` is the emptiness answer (see `nonEmptySql`). `total` is the pre-0.43
 * numeric form of the same question and is still honoured, so an external caller
 * of this exported helper is not silently re-classified by the switch.
 *
 * @returns {{status:'leak'|'safe'|'not-proven', viaRls?:boolean, message?:string}}
 */
export function classifyRead({ kind = 'table', rlsEnabled, canSelect, nonempty, total, anonVisible, anonVisibleCapped = false, role = 'anon' }) {
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
    return { status: 'leak', viaRls: true, message: `"${role}" can read ${anonVisible}${anonVisibleCapped ? '+' : ''} row(s) through this ${KIND_LABEL[kind]} — ${why} (proven by probe)` };
  }
  // Emptiness decides "anon saw none of N rows" (safe) from "there were no rows to
  // see" (proved nothing). Neither key given means the question was never asked —
  // a skip is not a pass, so say so rather than returning 'safe'. check() asks
  // under exactly the condition that reaches this line, so this branch is defence,
  // not an expected path.
  const empty = nonempty !== undefined ? nonempty === false
    : total !== undefined ? total === 0
      : null;
  if (empty === null) {
    return { status: 'not-proven', message: `could not determine whether this ${KIND_LABEL[kind].toLowerCase()} holds any rows, so the "${role}" probe proved nothing either way` };
  }
  if (empty) {
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
  const intro = introspectionSql(cfg.schemas, cfg.tenantColumns, role);
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
    // Read the privileged surface BEFORE dropping role: the SELECT grant always,
    // and emptiness ONLY where emptiness can change the verdict.
    for (const t of tables) {
      // Each relation in its own savepoint. Some relations raise when read: a
      // materialized view created WITH NO DATA raises 55000, which threw straight
      // out of check() and lost the ENTIRE scan — every real leak with it.
      // Verified: a database with an unpopulated matview and a genuinely
      // anon-readable table reported nothing at all, because the whole run
      // aborted.
      await query('savepoint tg_r', []);
      try {
        const s = readSurfaceSql(t.schema, t.name, role);
        const row = (await q(s.text, s.values))[0];
        t.canSelect = row.can_select === true || row.can_select === 't';
        // Ask emptiness under exactly the condition `classifyRead` consults it:
        // there is a grant AND the structural table rule has not already settled
        // it. Everything else — every relation anon cannot select at all, which is
        // most of them in a locked-down database — is now never touched by this
        // pass. Measured: on a 200k-row table with no anon grant the old pre-pass
        // spent 24 ms producing a number that `classifyRead` never read.
        if (t.canSelect && (t.kind !== 'table' || t.rlsEnabled)) {
          const e = nonEmptySql(t.schema, t.name);
          const erow = (await q(e.text, e.values))[0];
          t.nonempty = erow.nonempty === true || erow.nonempty === 't';
        }
        await query('release savepoint tg_r', []);
      } catch (err) {
        try { await query('rollback to savepoint tg_r', []); await query('release savepoint tg_r', []); }
        catch { /* the outer rollback still discards everything */ }
        t.introspectError = err.message;
        t.canSelect = false;
        t.nonempty = undefined;
      }
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
      // A relation we could not read privileged was never examined — say so
      // rather than counting it as clean.
      if (t.introspectError) {
        notes.push({
          where: `${t.schema}.${t.name}`,
          message: `not examined — reading it as the privileged role failed (${String(t.introspectError).slice(0, 110)}). A materialized view created WITH NO DATA does this. Isolation is NOT proven here.`,
        });
        continue;
      }
      scanned++;
      let anonVisible = 0;
      let anonVisibleCapped = false;
      // Probe whenever anon holds a grant and the structural rule doesn't already
      // settle it. Views ALWAYS get probed (see classifyRead) — their
      // relrowsecurity is meaninglessly false. Same predicate as the emptiness
      // question above, deliberately: the two answers are consumed together.
      if (t.canSelect && (t.kind !== 'table' || t.rlsEnabled)) {
        await query('savepoint tg_r', []);
        try {
          const c = anonSelectCountSql(t.schema, t.name);
          anonVisible = (await q(c.text, c.values))[0].n;
          // The probe counts to ANON_PROBE_CAP + 1; saturating means "at least
          // this many", so the message says 1000+ rather than a wrong exact count.
          if (anonVisible > ANON_PROBE_CAP) { anonVisible = ANON_PROBE_CAP; anonVisibleCapped = true; }
        } catch { /* denied => 0 */ }
        await query('rollback to savepoint tg_r', []);
        await query('release savepoint tg_r', []);
      }
      const verdict = classifyRead({ kind: t.kind, rlsEnabled: t.rlsEnabled, canSelect: t.canSelect, nonempty: t.nonempty, anonVisible, anonVisibleCapped, role });
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
