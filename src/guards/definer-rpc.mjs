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
import { parameterNames } from './identity-trust.mjs';

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
           p.proconfig as config,
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
/**
 * Does the app role hold CREATE on any schema? That is the precondition for
 * exploiting an unpinned `search_path` — you can only shadow an object if you can
 * create one. Without it, an unpinned search_path is untidy rather than dangerous.
 */
export function schemaCreateSql(role) {
  return {
    text: `select n.nspname as schema
             from pg_catalog.pg_namespace n
            where n.nspname not like 'pg\\_%' and n.nspname <> 'information_schema'
              and pg_catalog.has_schema_privilege($1::text, n.oid, 'CREATE')`,
    values: [role],
  };
}

/**
 * SQL **injection inside a `SECURITY DEFINER` function** — dynamic SQL built by
 * concatenating a caller-supplied parameter.
 *
 * This is not generic SAST, and it is not in scope because "injection is bad". It
 * is here because in this specific shape injection *is* a tenant-isolation
 * failure: the injected SQL executes as the function's **owner**, so it bypasses
 * RLS completely. A verified example — the table's policy is perfect, and
 * `search_notes("%' or true --")` returns every tenant's rows.
 *
 * Deliberately narrow, so a finding is never a guess. Two unambiguous shapes:
 *   • the parameter is `||`-concatenated into the string given to `EXECUTE`;
 *   • it is passed to `format()` through **`%s`**, which does no escaping at all.
 * `quote_literal()`, `quote_ident()`, `format('%L'/'%I')` and `EXECUTE … USING`
 * are all correct and produce no finding. Anything this can't read confidently
 * produces no finding either — silence beats a guess.
 *
 * @returns {{param:string, via:'concat'|'format-%s', snippet:string}|null}
 */
export function dynamicSqlInjection(body, params = []) {
  const s = String(body || '');
  if (!/\bexecute\b/i.test(s) || params.length === 0) return null;
  // Each EXECUTE's SQL expression: everything up to USING / end of statement.
  const stmts = [...s.matchAll(/\bexecute\b([\s\S]*?)(?:\busing\b|;|$)/gi)].map((m) => m[1]);
  for (const stmt of stmts) {
    for (const p of params) {
      if (!new RegExp(`\\b${p}\\b`).test(stmt)) continue;
      // Correctly quoted => not a finding.
      if (new RegExp(`(quote_literal|quote_ident)\\s*\\(\\s*${p}\\b`, 'i').test(stmt)) continue;
      const fmt = stmt.match(/\bformat\s*\(\s*'((?:[^']|'')*)'/i);
      if (fmt) {
        // format() is only unsafe through %s; %L and %I escape properly.
        if (/%s/.test(fmt[1])) return { param: p, via: 'format-%s', snippet: stmt.trim().slice(0, 140) };
        continue;
      }
      // Bare concatenation of the parameter into the SQL string.
      if (new RegExp(`\\|\\|[^;]*\\b${p}\\b|\\b${p}\\b[^;]*\\|\\|`).test(stmt)) {
        return { param: p, via: 'concat', snippet: stmt.trim().slice(0, 140) };
      }
    }
  }
  return null;
}

/** Is `search_path` pinned on this function? (`proconfig` holds `SET` clauses.) */
export function searchPathPinned(config) {
  return Array.isArray(config) && config.some((c) => /^search_path=/i.test(String(c)));
}

/**
 * The schemas a pinned `search_path` actually resolves through.
 *
 * `proconfig` stores the clause verbatim - `search_path=public, app` - so the
 * entries have to be split back out. `$user` is dropped: it resolves to a schema
 * named after the CURRENT user, which for a definer function is the owner, and
 * it is not a fixed name that can be checked against a grant list.
 */
export function searchPathSchemas(config) {
  const entry = (config ?? []).map(String).find((c) => /^search_path=/i.test(c));
  if (!entry) return [];
  return entry
    .slice(entry.indexOf('=') + 1)
    .split(',')
    .map((x) => x.trim().replace(/^"(.*)"$/, '$1'))
    .filter((x) => x && x.toLowerCase() !== '$user');
}

/**
 * Is the pin worth anything?
 *
 * A pin that names a schema the attacker can CREATE in is not protection - it
 * just fixes the path they were going to be on anyway. **Verified**: a definer
 * function pinned `SET search_path = public, app`, with `public` writable by a
 * lower-privileged role, returned that role's planted table instead of the
 * owner's. Pinned `= app, public` returned the real one. The ORDER matters and
 * the writability matters; the presence of a `SET` clause on its own means
 * nothing, which is exactly what this used to check.
 *
 * Only entries BEFORE the first schema the role cannot write to can be
 * shadowed - once resolution reaches a schema they cannot plant in, the real
 * object wins. `pg_catalog` is not writable, which is why
 * `SET search_path = pg_catalog, ...` is the canonical fix.
 *
 * Returns the writable schemas that are actually reachable, [] if the pin holds.
 */
export function shadowableSchemas(config, writableSchemas = []) {
  const writable = new Set(writableSchemas);
  const out = [];
  for (const schema of searchPathSchemas(config)) {
    if (schema.toLowerCase() === 'pg_catalog') break; // no longer hijackable past here
    if (writable.has(schema)) out.push(schema);
    else break; // the real object resolves here; nothing later can be shadowed
  }
  return out;
}

/**
 * The hole in every "just pin it" answer, including the one this guard used to
 * print: **`pg_temp` is searched BEFORE every schema you list unless you name it
 * explicitly.** `TEMP` on the database is granted to `PUBLIC` by default in every
 * Postgres version, so any role that can open a session can create a temp table
 * and shadow an unqualified name inside the function — with no CREATE anywhere.
 *
 * Measured, with `CREATE ON SCHEMA public` revoked so the attacker had nowhere
 * else to plant:
 *
 *     SET search_path = pg_catalog, app              -> TEMP-HIJACKED
 *     SET search_path = pg_catalog, app, pg_temp     -> legit
 *     SET search_path = ''  (unqualified body)       -> the function BREAKS
 *     SET search_path = ''  (qualified body)         -> legit
 *
 * So naming `pg_temp` last is the fix that is safe to apply without also editing
 * the body — and `search_path = ''` is NOT, which is worth knowing before
 * repeating the advice that is usually given for this.
 */
export function temporarilyShadowable(config) {
  const schemas = searchPathSchemas(config);
  if (!schemas.length) return false; // unpinned: reported by the caller anyway
  return !schemas.some((x) => x.toLowerCase() === 'pg_temp');
}

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

  // Precondition for the search_path hijack: you can only shadow an object if
  // you can create one. Without CREATE anywhere, an unpinned path is untidy, not
  // dangerous — and saying so is the difference between a finding and noise.
  let writableSchemas = [];
  try {
    const sc = schemaCreateSql(role);
    writableSchemas = (await q(sc.text, sc.values)).map((r) => r.schema);
  } catch { /* optional */ }

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
      const fqn = `${fn.schema}.${fn.name}(${fn.args || ''})`;

      // ── body checks: these read the source, so unlike the probe they apply to
      // VOLATILE functions too — which matters, because plpgsql defaults to
      // VOLATILE and that is exactly where dynamic SQL lives.
      if (canExecute) {
        const inj = dynamicSqlInjection(fn.body, parameterNames(fn.args));
        if (inj) {
          violations.push({
            where: fqn,
            kind: 'sql-injection',
            message:
              `SQL INJECTION in a SECURITY DEFINER function: the "${inj.param}" argument is ${inj.via === 'concat' ? 'concatenated straight into' : 'passed through format() with %s into'} the SQL given to EXECUTE, and "${role}" may call it. ` +
              `Injected SQL runs as the function's OWNER, so it bypasses RLS entirely — a caller can append "or true --" and read every tenant's rows however correct the table's policies are. ` +
              `Near: ${inj.snippet}`,
            fix:
              `Bind the value instead of building SQL out of it:\n` +
              `        EXECUTE 'select … where note like $1' USING ${inj.param};\n` +
              `      If it must be interpolated, escape it explicitly — quote_literal(${inj.param}) for a value, quote_ident(${inj.param}) for an identifier, or format('… %L …', ${inj.param}). Note that format's %s does NO escaping at all.`,
          });
        }
        const pinned = searchPathPinned(fn.config);
        // A pin that names a writable schema is not a pin. Verified: pinned
        // `= public, app` with `public` writable returned the attacker's planted
        // table; `= app, public` returned the real one.
        const shadowable = pinned ? shadowableSchemas(fn.config, writableSchemas) : [];
        const tempOpen = pinned && shadowable.length === 0 && temporarilyShadowable(fn.config);
        if ((!pinned && writableSchemas.length > 0) || shadowable.length > 0 || tempOpen) {
          const reachable = pinned ? shadowable : writableSchemas;
          violations.push({
            where: fqn,
            kind: 'search-path',
            message: tempOpen
              ? `SECURITY DEFINER function whose search_path is pinned, but does not name pg_temp — so the pin is incomplete. ` +
                `Postgres searches pg_temp BEFORE every schema you list unless you name it, and TEMP on the database is granted to PUBLIC by default, so any role that can open a session can create a temp table and shadow an unqualified name inside this function. It needs no CREATE privilege anywhere. ` +
                `Measured with CREATE ON SCHEMA public revoked: pinned "pg_catalog, ${fn.schema}" the function ran the attacker's temp table; with pg_temp named last it ran the real one.`
              : pinned
              ? `SECURITY DEFINER function whose search_path is pinned to ${shadowable.map((s) => `"${s}"`).join(', ')} — which "${role}" can CREATE objects in, so the pin protects nothing. ` +
                `Resolution walks the pinned path in order and reaches a schema they can plant in before it reaches yours, so an unqualified name in the body finds THEIR object, executing as the owner with RLS bypassed. ` +
                `Verified against a real database: a function pinned to a writable schema returned a planted table; the same function pinned to its own schema first returned the real one.`
              : `SECURITY DEFINER function with no pinned search_path, and "${role}" can CREATE objects in ${writableSchemas.slice(0, 3).map((s) => `"${s}"`).join(', ')}. ` +
                `Unqualified names inside the function resolve through the CALLER's search_path, so a caller who creates a table or function earlier on that path makes this function operate on THEIR object — executing as the definer's owner, with RLS bypassed.`,
            fix:
              `Pin it to a path nobody can plant on, and name pg_temp so it is searched LAST:\n` +
              `        ALTER FUNCTION ${fn.schema}.${fn.name}(${fn.args || ''}) SET search_path = pg_catalog, ${fn.schema}, pg_temp;\n` +
              `      pg_temp is the part that gets left out. Postgres searches it BEFORE everything you list unless you name it, and TEMP is granted to PUBLIC by default — so without it the pin is defeated by a temp table, needing no CREATE privilege anywhere.\n` +
              `      Verified: pinned "pg_catalog, ${fn.schema}" the function ran a planted temp table; with pg_temp named last it ran the real one.\n` +
              (reachable.length ? `      ${reachable.map((s) => `"${s}"`).join(', ')} must also not come before your own schema — "${role}" can CREATE there.\n` : '') +
              `      The strictest form is SET search_path = '' with every reference schema-qualified inside the body. Do NOT apply that one blindly: with an unqualified body the function stops working ("relation does not exist").`,
          });
        } else if (!pinned) {
          notes.push({ where: fqn, message: `SECURITY DEFINER function with no pinned search_path. Not exploitable here — "${role}" cannot CREATE objects in any schema, so it has nowhere to plant a shadowing object — but pinning it (SET search_path = pg_catalog, ${fn.schema}) keeps it that way.` });
        }
      }

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
