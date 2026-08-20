/**
 * Guard: `SECURITY DEFINER` RPCs that hand out other tenants' rows.
 *
 * This is the purest form of "the policy exists but the access path around it
 * breaks the boundary". A `SECURITY DEFINER` function runs as its **owner**, so
 * it bypasses RLS on everything it touches. If the body doesn't re-filter by an
 * auth-derived tenant — or worse, filters by a tenant id the **caller passes in**
 * — then a flawless set of policies is simply routed around:
 *
 *     create function get_invoices(org text) returns setof invoices
 *       language sql security definer stable
 *       as $$ select * from invoices where organization_id = org $$;
 *     grant execute on function get_invoices(text) to authenticated;
 *
 * `invoices` can have perfect RLS. Every table-level guard reports green. And any
 * logged-in user calls `get_invoices('<someone else>')` and gets their data,
 * because PostgREST exposes every such function at `/rest/v1/rpc/<name>`.
 *
 * **Why this is safe to probe, which is the part that kept it unbuilt.** Calling
 * an arbitrary definer function is genuinely dangerous: the body is unknown, and
 * side effects (an autonomous commit through dblink, a NOTIFY, a consumed
 * sequence) survive the rollback that makes every other guard here harmless. The
 * resolution is in the catalog: Postgres **enforces** that a non-`VOLATILE`
 * function cannot write — attempting an INSERT inside a `STABLE` function raises
 * *"INSERT is not allowed in a non-volatile function"*. So:
 *
 *   • `STABLE` / `IMMUTABLE` definer functions are **called** — the engine
 *     guarantees they cannot modify anything;
 *   • `VOLATILE` definer functions are **never called**. They are reported from a
 *     read of their body, as a note, with that limitation stated — because an
 *     unprovable finding presented as proven is worse than no finding.
 *
 * Arguments are only supplied where they can be supplied meaningfully: a
 * zero-argument function is called directly, and a single tenant-shaped
 * text/uuid argument is called with another tenant's id. Anything else is skipped
 * rather than guessed at. Read-only, inside a rolled-back transaction.
 */
import {
  quoteIdent,
  qualified,
  safeRole,
  buildBecomeTenant,
  isPermissionDenied,
  applyClaimShortcut,
  introspectionSql,
  planTables,
  distinctTenantsSql,
  DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';

export const meta = {
  id: 'definer-rpc',
  title: 'SECURITY DEFINER RPCs that route around RLS',
  why: "A SECURITY DEFINER function runs as its owner and bypasses RLS on everything it touches, and PostgREST exposes it as an endpoint. If it doesn't re-filter by an auth-derived tenant — or trusts a tenant id the caller passes in — a flawless set of policies is simply routed around, and every table-level check still reports green.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  role: PROOF_DEFAULTS.role,
  becomeTenant: PROOF_DEFAULTS.becomeTenant,
  claim: null,
  allowlist: [], // "schema.function" that is intentionally cross-tenant (an admin RPC)
  // Argument types we will supply a tenant id for. Anything else is skipped
  // rather than guessed at.
  tenantArgTypes: ['text', 'character varying', 'uuid'],
};

/** A tenant id that cannot exist — the control arm for argument-trusting RPCs. */
export const NONEXISTENT_TENANT = '__tenant_guard_no_such_tenant__';

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Every SECURITY DEFINER function in `schemas`, with what we need to decide
 * whether it is safe to call and whether the caller can even reach it.
 * `provolatile` is the load-bearing column: 'v' = volatile (never called),
 * 's'/'i' = stable/immutable, which Postgres guarantees cannot write.
 */
export function definerRpcSql(schemas, role) {
  const text = `
    select n.nspname as schema,
           p.proname as name,
           pg_catalog.pg_get_function_identity_arguments(p.oid) as args,
           pg_catalog.pg_get_function_result(p.oid) as returns,
           p.provolatile as volatility,
           p.pronargs::int as nargs,
           p.prosrc as body,
           pg_catalog.has_function_privilege($2::text, p.oid, 'EXECUTE') as can_execute,
           (select array_agg(pg_catalog.format_type(t, null) order by ord)
              from unnest(p.proargtypes) with ordinality as u(t, ord)) as arg_types
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where p.prosecdef
      and n.nspname = any($1)
      and pg_catalog.pg_get_function_result(p.oid) <> 'trigger'
    order by 1, 2`;
  return { text, values: [schemas, role] };
}

/** Postgres guarantees a non-volatile function cannot modify the database. */
export function isReadOnlyVolatility(volatility) {
  return volatility === 's' || volatility === 'i';
}

/**
 * Does this function body ever consult the caller's *identity*? A definer
 * function that never mentions `auth.uid()` / `request.jwt` / a tenant GUC has
 * nothing to re-filter by, which is the smell — but it is only a smell, since the
 * body could scope by something we don't recognise.
 */
export function bodyConsultsIdentity(body) {
  return /auth\.uid\s*\(|auth\.jwt\s*\(|auth\.role\s*\(|request\.jwt|current_setting\s*\(/i.test(body || '');
}

/** Does the body reference any of the tenant-scoped tables we know about? */
export function bodyTouchesTenantTable(body, tenantTables = []) {
  const s = String(body || '');
  return tenantTables.some((t) => new RegExp(`\\b${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(s));
}

/**
 * How (and whether) we can call this function.
 * @returns {{mode:'no-args'|'tenant-arg'|'skip', reason?:string}}
 */
export function planCall({ nargs, argTypes = [], tenantArgTypes = DEFAULTS.tenantArgTypes }) {
  if (nargs === 0) return { mode: 'no-args' };
  if (nargs === 1) {
    const t = (argTypes[0] || '').toLowerCase();
    if (tenantArgTypes.includes(t)) return { mode: 'tenant-arg', argType: t };
    return { mode: 'skip', reason: `single ${argTypes[0]} argument is not a tenant-shaped type` };
  }
  return { mode: 'skip', reason: `${nargs} arguments — tenant-guard won't invent values for them` };
}

/** `select count(*) from schema.fn()` filtered to rows NOT belonging to `$1`. */
export function noArgProbeSql(schema, name, tenantColumn) {
  return {
    text: `select count(*)::int as n from ${qualified(schema, name)}() x where x.${quoteIdent(tenantColumn)}::text <> $1`,
  };
}

/** `select count(*) from schema.fn($1::type)` — call it with another tenant's id. */
export function tenantArgProbeSql(schema, name, argType) {
  if (!DEFAULTS.tenantArgTypes.includes(String(argType).toLowerCase())) {
    throw new Error(`unsafe argument type for probing: ${JSON.stringify(argType)}`);
  }
  return { text: `select count(*)::int as n from ${qualified(schema, name)}($1::${argType}) x` };
}

/**
 * Verdict for one definer RPC.
 * @returns {{status:'leak'|'safe'|'note'|'skip', kind?:string, message?:string, fix?:string}}
 */
export function classifyRpc({ schema, name, args, volatility, canExecute, mode, foreignRows, controlRows, consultsIdentity, touchesTenantTable, role = 'authenticated' }) {
  const fqn = `${schema}.${name}(${args || ''})`;
  if (!canExecute) return { status: 'skip', reason: `"${role}" cannot EXECUTE it` };

  if (!isReadOnlyVolatility(volatility)) {
    // Never called: a VOLATILE body may write, and a write can outlive our rollback.
    if (touchesTenantTable && !consultsIdentity) {
      return {
        status: 'note',
        kind: 'unproven',
        message:
          `VOLATILE SECURITY DEFINER function that "${role}" may EXECUTE. Its body reads a tenant-scoped table and never mentions auth.uid() / request.jwt / a tenant GUC, so it appears not to re-filter by the caller's tenant — and being SECURITY DEFINER it bypasses RLS entirely. ` +
          `NOT PROVEN: tenant-guard will not call a VOLATILE function, because an unknown body can commit autonomously or fire side effects that a rollback cannot undo. Review it by hand, or mark it STABLE if it really is read-only and let this guard prove it.`,
      };
    }
    return { status: 'skip', reason: 'volatile — not called, and no static smell' };
  }

  if (mode === 'tenant-arg' && foreignRows > 0) {
    // Control arm: a function that returns the same rows for a nonexistent tenant
    // ignores its argument entirely — that's the no-filter shape, not arg-trusting.
    const ignoresArg = controlRows > 0;
    return {
      status: 'leak',
      kind: ignoresArg ? 'no-filter' : 'trusts-argument',
      message: ignoresArg
        ? `"${role}" called this SECURITY DEFINER function and got ${foreignRows} row(s) belonging to another tenant — and it returns rows even for a tenant id that cannot exist, so it isn't filtering by tenant at all. Being SECURITY DEFINER it runs as its owner and bypasses RLS, so the policies on the underlying tables never apply`
        : `"${role}" called this SECURITY DEFINER function with ANOTHER TENANT'S id and got ${foreignRows} of their row(s) back. The function trusts a tenant id the caller passes in, and being SECURITY DEFINER it bypasses RLS — so however correct the table's policies are, PostgREST exposes this at /rest/v1/rpc/${name} and any logged-in user can read any tenant`,
      fix:
        `Derive the tenant inside the function from the verified session, never from an argument:\n` +
        `        where organization_id = (auth.jwt() -> 'app_metadata' ->> 'org_id')\n` +
        `      If the argument is genuinely needed, authorize it first:\n` +
        `        if not exists (select 1 from memberships where user_id = auth.uid() and org_id = <arg>) then raise exception 'forbidden'; end if;\n` +
        `      Or drop SECURITY DEFINER entirely so the caller's own RLS applies, or REVOKE EXECUTE ON FUNCTION ${fqn} FROM ${role};`,
    };
  }

  if (mode === 'no-args' && foreignRows > 0) {
    return {
      status: 'leak',
      kind: 'no-filter',
      message: `"${role}" called this SECURITY DEFINER function and got ${foreignRows} row(s) belonging to another tenant. It runs as its owner, so RLS on the underlying tables does not apply to it, and it isn't re-filtering by the caller's tenant`,
      fix:
        `Re-filter inside the function by the verified session:\n` +
        `        where organization_id = (auth.jwt() -> 'app_metadata' ->> 'org_id')\n` +
        `      Or drop SECURITY DEFINER so the caller's own RLS applies, or REVOKE EXECUTE ON FUNCTION ${fqn} FROM ${role};`,
    };
  }

  return { status: 'safe' };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = applyClaimShortcut({ ...DEFAULTS, ...config }, config);
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;
  const skip = new Set(cfg.allowlist);

  const dr = definerRpcSql(cfg.schemas, role);
  const fns = (await q(dr.text, dr.values)).filter((f) => !skip.has(`${f.schema}.${f.name}`) && !skip.has(f.name));
  if (fns.length === 0) {
    return OK({ skipped: true, reason: `no SECURITY DEFINER functions in ${cfg.schemas.join(', ')}`, summary: 'skipped — no definer functions' });
  }

  // Which tables are tenant-scoped, and two real tenant ids to probe with.
  const intro = introspectionSql(cfg.schemas, cfg.tenantColumns, role);
  const plan = planTables(await q(intro.text, intro.values), cfg.tenantColumns);
  const tenantTables = plan.map((t) => t.table);
  let tenantA = null;
  let tenantB = null;
  let tenantColumn = cfg.tenantColumns[0];
  for (const t of plan) {
    try {
      const d = distinctTenantsSql(t.schema, t.table, t.tenantColumn, 2);
      const ts = (await q(d.text, d.values)).map((r) => r.t);
      if (ts.length >= 2) { [tenantA, tenantB] = ts; tenantColumn = t.tenantColumn; break; }
    } catch { /* try the next table */ }
  }

  const violations = [];
  const notes = [];
  let scanned = 0;
  let proven = 0;

  await query('begin', []);
  try {
    // Negative control: the app role must actually be subject to RLS.
    let canaryReady = false;
    try {
      await query('create temp table tg_rpc_canary (x int)', []);
      await query('insert into tg_rpc_canary values (1)', []);
      await query('alter table tg_rpc_canary enable row level security', []);
      await query('alter table tg_rpc_canary force row level security', []);
      await query(`grant select on tg_rpc_canary to ${role}`, []);
      canaryReady = true;
    } catch (err) {
      notes.push({ where: '(self-check)', message: `could not set up the RLS self-check canary (${err.message})` });
    }
    await query(`set local role ${role}`, []);
    if (canaryReady) {
      let seen = null;
      try { seen = (await q('select count(*)::int as n from tg_rpc_canary', []))[0].n; } catch { /* denied => enforced */ }
      if (seen !== null && seen > 0) {
        try { await query('rollback', []); } catch { /* ignore */ }
        return {
          id: meta.id, ok: false, notes, scanned: 0,
          violations: [{ where: `role "${role}"`, message: `identity self-check FAILED — "${role}" read a deny-all RLS table, so RLS is NOT enforced for it. Every "safe" result would be a vacuous pass.`, fix: `Set the role to your non-superuser app role (e.g. "authenticated").` }],
          summary: 'identity switch is not enforcing RLS — refusing to report a vacuous pass',
        };
      }
    }
    if (tenantA) for (const s of buildBecomeTenant(cfg.becomeTenant, tenantA)) await query(s.text, s.values);

    for (const fn of fns) {
      const canExecute = fn.can_execute === true || fn.can_execute === 't';
      const call = planCall({ nargs: Number(fn.nargs), argTypes: fn.arg_types || [], tenantArgTypes: cfg.tenantArgTypes });
      const base = {
        schema: fn.schema, name: fn.name, args: fn.args, volatility: fn.volatility, canExecute, role,
        consultsIdentity: bodyConsultsIdentity(fn.body),
        touchesTenantTable: bodyTouchesTenantTable(fn.body, tenantTables),
      };

      // VOLATILE and unreachable functions never get called.
      if (!canExecute || !isReadOnlyVolatility(fn.volatility)) {
        const v = classifyRpc({ ...base, mode: call.mode });
        if (v.status === 'note') { scanned++; notes.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, message: v.message }); }
        continue;
      }
      if (call.mode === 'skip') {
        notes.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, message: `not probed — ${call.reason}. It is SECURITY DEFINER and callable by "${role}", so confirm by hand that it re-filters by the caller's tenant.` });
        continue;
      }
      if (!tenantA || !tenantB) {
        notes.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, message: `not probed — no two tenants of data found to compare with.` });
        continue;
      }

      scanned++;
      let foreignRows = 0;
      let controlRows = 0;
      try {
        if (call.mode === 'tenant-arg') {
          const p = tenantArgProbeSql(fn.schema, fn.name, call.argType);
          foreignRows = (await q(p.text, [tenantB]))[0].n;
          if (foreignRows > 0) controlRows = (await q(p.text, [NONEXISTENT_TENANT]))[0].n;
        } else {
          const p = noArgProbeSql(fn.schema, fn.name, tenantColumn);
          foreignRows = (await q(p.text, [tenantA]))[0].n;
        }
      } catch (err) {
        if (!isPermissionDenied(err)) {
          notes.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, message: `not probed — calling it errored (${err.message.slice(0, 120)}). This is usually a return shape without a tenant column, not a leak.` });
        }
        continue;
      }

      const verdict = classifyRpc({ ...base, mode: call.mode, foreignRows, controlRows });
      if (verdict.status === 'leak') {
        violations.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, kind: verdict.kind, message: verdict.message, fix: verdict.fix });
      } else if (verdict.status === 'safe') {
        proven++;
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
      violations.length > 0
        ? `${violations.length} SECURITY DEFINER RPC(s) return other tenants' rows`
        : `${proven}/${scanned} callable definer RPC(s) proven tenant-scoped` + (notes.length ? `; ${notes.length} not proven (see notes)` : ''),
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
