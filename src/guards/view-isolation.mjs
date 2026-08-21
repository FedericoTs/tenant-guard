/**
 * Guard: tenant isolation through VIEWS and MATERIALIZED VIEWS.
 *
 * This is the highest-severity class that every table-only checker misses —
 * including, until now, this tool's own `rls-proof` (which introspects base
 * tables). Two distinct Postgres mechanisms:
 *
 *   • A VIEW executes with its **owner's** privileges. So a view owned by
 *     `postgres` over a correctly-RLS'd `orders` table evaluates that RLS *as
 *     postgres* — and returns every tenant's rows to whoever can SELECT the view.
 *     PG15+ fixes this with `WITH (security_invoker = true)`, which is **off by
 *     default**. The base table looks perfectly locked down; the view beside it
 *     hands out the whole dataset.
 *
 *   • A MATERIALIZED VIEW is worse: row-level security **never applies to it at
 *     all**. It is a stored snapshot owned by whoever refreshes it, and there is
 *     no policy you can write to scope it per caller. Any role with SELECT reads
 *     every tenant. In Supabase both are auto-exposed by PostgREST and auto-
 *     granted to `anon`/`authenticated` by the default privileges.
 *
 * Like the rest of the tool it *probes* rather than guesses: it assumes tenant
 * A's identity as your real app role and reads the view. The catalog is used only
 * to explain **why** a leak happened (owner, `security_invoker`, kind) and to
 * pick the right fix — a materialized view can't be fixed with `security_invoker`,
 * and a view that already sets it means the leak is in the base table's policy.
 *
 * Scoped to views exposing a **tenant column**, so genuinely public views
 * (published content, reference data) are not flagged. Same negative control as
 * the other runtime guards. Read-only: one rolled-back transaction.
 */
import {
  qualified,
  safeRole,
  buildBecomeTenant,
  isPermissionDenied,
  distinctTenantsSql,
  tenantRowCountSql,
  applyClaimShortcut,
  DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';

export const meta = {
  id: 'view-isolation',
  title: 'Tenant isolation through views and materialized views',
  why: "Proves a tenant's session cannot read another tenant's rows through a VIEW or MATERIALIZED VIEW — views run with their owner's rights unless security_invoker is set, and RLS never applies to materialized views at all, so a perfectly-RLS'd table can still be handed out wholesale by the view beside it.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  role: PROOF_DEFAULTS.role,
  becomeTenant: PROOF_DEFAULTS.becomeTenant,
  claim: null,
  allowlist: [], // "schema.view" (or bare name) intentionally exposing all tenants
  sampleLimit: 3,
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Views + materialized views in `schemas` that expose one of `tenantColumns`. */
export function viewIntrospectionSql(schemas, tenantColumns) {
  const text = `
    select n.nspname                    as schema,
           c.relname                    as view,
           c.relkind                    as kind,
           a.attname                    as column,
           c.relowner::regrole::text    as owner_role,
           array_to_string(c.reloptions, ',') as reloptions
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    where c.relkind in ('v', 'm')
      and n.nspname = any($1)
      and a.attname = any($2)
    order by n.nspname, c.relname`;
  return { text, values: [schemas, tenantColumns] };
}

/** Does this view's reloptions turn on security_invoker? */
export function hasSecurityInvoker(reloptions) {
  return /\bsecurity_invoker\s*=\s*(true|on|1)\b/i.test(reloptions || '');
}

/**
 * One entry per view: the tenant column chosen by the priority order in
 * `tenantColumns`, its kind, owner, and whether security_invoker is set.
 * Allowlisted views are dropped.
 */
export function planViews(rows, tenantColumns, allowlist = []) {
  const skip = new Set(allowlist);
  const byView = new Map();
  for (const r of rows) {
    const key = `${r.schema}.${r.view}`;
    if (skip.has(r.view) || skip.has(key)) continue;
    const prio = tenantColumns.indexOf(r.column);
    if (prio < 0) continue;
    const existing = byView.get(key);
    if (!existing || prio < existing.prio) {
      byView.set(key, {
        schema: r.schema,
        view: r.view,
        id: key,
        kind: r.kind === 'm' ? 'matview' : 'view',
        tenantColumn: r.column,
        ownerRole: r.owner_role ?? null,
        securityInvoker: hasSecurityInvoker(r.reloptions),
        prio,
      });
    }
  }
  return [...byView.values()].map(({ prio, ...v }) => v);
}

const label = (kind) => (kind === 'matview' ? 'MATERIALIZED VIEW' : 'VIEW');

/**
 * The fix depends entirely on *which* mechanism leaked — this is why the guard
 * reads the catalog even though the verdict comes from the probe.
 */
export function fixForView({ kind, schema, view, securityInvoker, role, pgVersionNum }) {
  const q = qualified(schema, view);
  if (kind === 'matview') {
    return (
      `A materialized view CANNOT be scoped by RLS — there is no policy to add. Either:\n` +
      `        REVOKE SELECT ON ${q} FROM ${role};   -- and read the RLS-protected base table instead\n` +
      `      or move it out of the API-exposed schema, or rebuild it as a regular view:\n` +
      `        CREATE VIEW … WITH (security_invoker = true) AS …`
    );
  }
  if (securityInvoker) {
    return (
      `This view already sets security_invoker, so RLS was evaluated as the caller — ` +
      `the leak is in the UNDERLYING TABLE's policy, not the view. Run \`tenant-guard prove\` to find and fix it.`
    );
  }
  if (pgVersionNum && pgVersionNum < 150000) {
    return (
      `Your Postgres (${pgVersionNum}) predates security_invoker (PG15+). Either add the tenant predicate to the view's own definition, ` +
      `move it out of the API-exposed schema, or:\n        REVOKE SELECT ON ${q} FROM ${role};`
    );
  }
  return (
    `Make the view evaluate RLS as the CALLER, not its owner:\n` +
    `        ALTER VIEW ${q} SET (security_invoker = true);\n` +
    `      (then confirm the base table's own policy is correct — \`tenant-guard prove\`)`
  );
}

/**
 * Turn one view's measurements into a verdict.
 * @returns {{status:'isolated'|'leak'|'no-access'|'insufficient-data'|'over-restrictive', message?:string, fix?:string}}
 */
export function classifyViewResult({ kind, securityInvoker, ownerRole, ownVisible, crossVisible, tenantCount, noAccess, schema, view, role = 'authenticated', pgVersionNum }) {
  if (noAccess) {
    return { status: 'no-access', message: `"${role}" cannot read this ${label(kind)} at all (no SELECT grant) — nothing is exposed through it` };
  }
  if (tenantCount < 2) {
    return { status: 'insufficient-data', message: `only ${tenantCount} tenant(s) of data visible through this ${label(kind)} — cannot prove isolation until two tenants exist` };
  }
  if (crossVisible > 0) {
    let why;
    if (kind === 'matview') {
      why = `row-level security NEVER applies to a materialized view — it is a stored snapshot owned by "${ownerRole}", and no policy can scope it per caller, so any role holding SELECT reads every tenant`;
    } else if (securityInvoker) {
      why = `this view IS security_invoker (RLS was evaluated as the caller), so the leak is in the underlying table's policy — not in the view itself`;
    } else {
      why = `this view does not set security_invoker, so it runs with its OWNER's ("${ownerRole}") privileges and the base table's RLS was evaluated as the owner instead of the caller`;
    }
    return {
      status: 'leak',
      message: `tenant A's session READ ${crossVisible} row(s) belonging to tenant B through this ${label(kind)} — ${why}`,
      fix: fixForView({ kind, schema, view, securityInvoker, role, pgVersionNum }),
    };
  }
  if (ownVisible === 0) {
    return { status: 'over-restrictive', message: `the tenant session sees none of its own rows through this ${label(kind)} either — not proven (not a leak). Usually the role/becomeTenant config doesn't match your policies.` };
  }
  return { status: 'isolated' };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

/**
 * @param {(text:string, values?:any[]) => Promise<{rows:any[]}>} query
 * @param {object} config  see DEFAULTS
 */
export async function check({ query, config = {} }) {
  const cfg = applyClaimShortcut({ ...DEFAULTS, ...config }, config);
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;

  const intro = viewIntrospectionSql(cfg.schemas, cfg.tenantColumns);
  const plan = planViews(await q(intro.text, intro.values), cfg.tenantColumns, cfg.allowlist);
  if (plan.length === 0) {
    return OK({ skipped: true, reason: `no views or materialized views with a tenant column in ${cfg.schemas.join(', ')}`, summary: 'skipped — no tenant views' });
  }

  let pgVersionNum = null;
  try { pgVersionNum = Number((await q(`select current_setting('server_version_num') as v`, []))[0].v); } catch { /* optional */ }

  const violations = [];
  const notes = [];
  let scanned = 0;
  let proven = 0;

  await query('begin', []);
/**
   * Run one probe inside a savepoint.
   *
   * The guard does its whole scan in a single transaction. Without a savepoint,
   * ONE relation the app role cannot read aborts that transaction, and every
   * relation examined afterwards fails with 25P02 and is silently downgraded to a
   * note — so a real leak reports green, decided by nothing but sort order.
   * Reproduced. Six sibling guards already did it this way.
   */
  const savepointed = async (fn) => {
    await query('savepoint tg_v', []);
    try {
      const out = await fn();
      await query('release savepoint tg_v', []);
      return { ok: true, out };
    } catch (err) {
      try { await query('rollback to savepoint tg_v', []); await query('release savepoint tg_v', []); }
      catch { /* the outer rollback still discards everything */ }
      return { ok: false, err };
    }
  };
  try {
    // Privileged pass: which tenants are visible through each view at all.
    for (const v of plan) {
      const d = distinctTenantsSql(v.schema, v.view, v.tenantColumn, cfg.sampleLimit);
      const r = await savepointed(async () => (await q(d.text, d.values)).map((x) => x.t));
      if (r.ok) v.tenants = r.out;
      else { v.introspectError = r.err.message; v.tenants = []; }
    }

    // Negative control: the app role must be subject to RLS at all.
    let canaryReady = false;
    try {
      await query('create temp table tg_view_canary (x int)', []);
      await query('insert into tg_view_canary values (1), (2)', []);
      await query('alter table tg_view_canary enable row level security', []);
      await query('alter table tg_view_canary force row level security', []);
      await query(`grant select on tg_view_canary to ${role}`, []);
      canaryReady = true;
    } catch (err) {
      notes.push({ where: '(self-check)', message: `could not set up the RLS self-check canary (${err.message})` });
    }
    await query(`set local role ${role}`, []);
    if (canaryReady) {
      let seen = null;
      try { seen = (await q('select count(*)::int as n from tg_view_canary', []))[0].n; } catch { /* denied => enforced */ }
      if (seen !== null && seen > 0) {
        try { await query('rollback', []); } catch { /* ignore */ }
        return {
          id: meta.id, ok: false, notes, scanned: 0,
          violations: [{ where: `role "${role}"`, message: `identity self-check FAILED — "${role}" read a deny-all RLS table, so RLS is NOT enforced for it. Every "isolated" result would be a vacuous pass.`, fix: `Set the role to your non-superuser app role (e.g. "authenticated") — not a superuser, a BYPASSRLS role, or a table owner.` }],
          summary: 'identity switch is not enforcing RLS — refusing to report a vacuous pass',
        };
      }
    }

    for (const v of plan) {
      if (v.introspectError) {
        notes.push({ where: v.id, message: `could not sample tenants: ${v.introspectError}` });
        continue;
      }
      scanned++;
      if (v.tenants.length < 2) {
        notes.push({ where: v.id, message: classifyViewResult({ kind: v.kind, tenantCount: v.tenants.length, ownVisible: 0, crossVisible: 0, role }).message });
        continue;
      }
      const [tenantA, tenantB] = v.tenants;

      let noAccess = false;
      let probeError = null;
      let ownVisible = 0;
      let crossVisible = 0;
      const probe = await savepointed(async () => {
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantA)) await query(s.text, s.values);
        const own = tenantRowCountSql(v.schema, v.view, v.tenantColumn, tenantA);
        const cross = tenantRowCountSql(v.schema, v.view, v.tenantColumn, tenantB);
        const o = (await q(own.text, own.values))[0].n;
        let c = (await q(cross.text, cross.values))[0].n;

        // Reverse direction, same as rls-proof: B must not see A either.
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantB)) await query(s.text, s.values);
        const crossA = tenantRowCountSql(v.schema, v.view, v.tenantColumn, tenantA);
        c = Math.max(c, (await q(crossA.text, crossA.values))[0].n);
        return { o, c };
      });
      if (probe.ok) { ownVisible = probe.out.o; crossVisible = probe.out.c; }
      else if (isPermissionDenied(probe.err)) noAccess = true;
      else probeError = probe.err.message;

      if (probeError) {
        notes.push({ where: v.id, message: `could not probe — check role/becomeTenant: ${probeError}` });
        continue;
      }

      const verdict = classifyViewResult({
        kind: v.kind, securityInvoker: v.securityInvoker, ownerRole: v.ownerRole,
        ownVisible, crossVisible, tenantCount: v.tenants.length, noAccess,
        schema: v.schema, view: v.view, role, pgVersionNum,
      });
      if (verdict.status === 'leak') {
        violations.push({ where: `${v.id} (${v.tenantColumn})`, kind: v.kind, message: verdict.message, fix: verdict.fix, crossVisible });
      } else if (verdict.status === 'isolated') {
        proven++;
      } else {
        notes.push({ where: v.id, message: verdict.message });
      }
    }
  } finally {
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  const notProven = scanned - proven - violations.length;
  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length > 0
        ? `${violations.length} view(s)/materialized view(s) leak across tenants`
        : `${proven}/${scanned} tenant view(s) proven isolated` + (notProven > 0 ? `; ${notProven} not proven (see notes)` : ''),
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
