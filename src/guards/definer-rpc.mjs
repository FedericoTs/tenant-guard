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
 * **What calling a definer function costs, stated accurately.** Calling an
 * arbitrary definer function is genuinely dangerous: the body is unknown, and
 * side effects (an autonomous commit through dblink, a NOTIFY, a consumed
 * sequence) survive the rollback that makes every other guard here harmless. The
 * volatility declaration narrows that, and this file used to claim it closed it.
 * It does not. Two things are true and were measured on PG 18.3:
 *
 *   • Postgres does refuse a direct write inside a non-`VOLATILE` function —
 *     an INSERT in a `STABLE` body raises *"INSERT is not allowed in a
 *     non-volatile function"*, and a table write reached that way is undone by
 *     the rollback (audit_log stayed at 0 rows).
 *   • The flag is per-function and is **not** inherited. `provolatile` is an
 *     author declaration Postgres never verifies against the body. A `STABLE`
 *     function whose body calls a `VOLATILE` helper executes that helper's
 *     INSERT, and a `STABLE` body may call `nextval` directly. Running this
 *     guard's own `check()` over `select * from invoices where
 *     nextval('setof_seq') > 0` left the sequence at {last_value: 3,
 *     is_called: true} after the rollback, up from {1, false}. The same
 *     mechanism reaches `dblink_exec`.
 *
 * So the rule is a risk budget, not a guarantee:
 *
 *   • `STABLE` / `IMMUTABLE` definer functions are **called**. The rollback
 *     contains table writes. It does not contain sequence consumption, NOTIFY,
 *     or anything a called `VOLATILE` helper commits out of band. Point this at a
 *     disposable database — README and docs/CI.md say so for the same reason.
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

/**
 * The control arm needs a tenant id that certainly does not exist — and it has
 * to be VALID for the argument's type.
 *
 * The text sentinel above cannot be cast to `uuid`: `'__tenant_guard_no_such_
 * tenant__'::uuid` raises 22P02. That mattered, because `uuid` is the ordinary
 * Supabase tenant type — the probe had already MEASURED a cross-tenant read, and
 * then the control arm threw, the measurement was discarded, and the run went
 * green on a proven leak. Reproduced: identical scenario with a `text` argument
 * failed the build, with `uuid` it passed.
 *
 * The all-zero uuid is used rather than a random one so the probe is
 * deterministic; a row actually carrying it would show up as a non-zero control
 * count, which `classifyRpc` already reads as "this function has no filter"
 * rather than as a clean result.
 */
export const NONEXISTENT_TENANT_UUID = '00000000-0000-0000-0000-000000000000';

/** The sentinel that is valid for this argument type. */
export function sentinelFor(argType) {
  return /uuid/i.test(String(argType ?? '')) ? NONEXISTENT_TENANT_UUID : NONEXISTENT_TENANT;
}

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Every SECURITY DEFINER function in `schemas`, with what we need to decide
 * whether it is safe to call and whether the caller can even reach it.
 * `provolatile` is the load-bearing column: 'v' = volatile (never called),
 * 's'/'i' = stable/immutable, which Postgres refuses to let write DIRECTLY. It is
 * an author declaration, not a verified property — see the header.
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

/**
 * Does the app role hold CREATE on any schema? That is the precondition for
 * planting a **permanent** shadow on an unpinned `search_path`.
 *
 * It is NOT the precondition for the hijack in general, and this used to be
 * written as if it were. `pg_temp` is searched before everything else and `TEMP`
 * on the database is granted to `PUBLIC` by default, so the shadow can be a temp
 * table with no CREATE grant anywhere — measured, see `tempCreateSql` and the
 * note branch in `check`. This query answers one question only: where could they
 * plant something that outlives the session.
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
 * Can the role create temp objects? `TEMP` on the database is granted to `PUBLIC`
 * by default in every Postgres version, so this is almost always true — which is
 * exactly why the "cannot CREATE anywhere, therefore safe" claim this replaces
 * was wrong. Measured on PG 18.3 with `CREATE` revoked on every schema and
 * `has_schema_privilege(...,'CREATE')` returning the empty set: `create temp
 * table invoices(...)` still made an unpinned definer function read the planted
 * table instead of the owner's.
 */
export function tempCreateSql(role) {
  return {
    text: `select pg_catalog.has_database_privilege($1::text, current_database(), 'TEMP') as temp`,
    values: [role],
  };
}

/** Every relation in the scanned schemas — what an unqualified name could mean. */
export function relationsSql(schemas) {
  return {
    text: `select n.nspname as schema, c.relname as name
             from pg_catalog.pg_class c
             join pg_catalog.pg_namespace n on n.oid = c.relnamespace
            where c.relkind in ('r','p','v','m','f')
              and n.nspname = any($1)`,
    values: [schemas],
  };
}

/**
 * Unqualified references in the body to relations that really exist.
 *
 * This exists to make the emitted `ALTER FUNCTION … SET search_path` **runnable**.
 * The fix used to interpolate `fn.schema` — where the FUNCTION lives, which is
 * not where its tables live. Measured: a definer function in `public` whose body
 * reads an unqualified `invoices` that lives in `app` worked before the guard's
 * own fix and raised `42P01 relation "invoices" does not exist` after it. Pasting
 * that ALTER into production takes the function down.
 *
 * Only names that match a real relation are returned, so this is a resolution and
 * not a guess. CTE names are dropped — they resolve inside the query, never
 * through `search_path` — and a name already carrying a schema prefix is skipped.
 * Quoted identifiers are not matched: a miss here costs a less specific fix, a
 * wrong hit costs a broken ALTER.
 *
 * @returns {Array<{name:string, schemas:string[]}>}
 */
export function unqualifiedRelationRefs(body, relations = []) {
  const s = String(body || '');
  if (!s || !relations.length) return [];

  const ctes = new Set();
  for (const m of s.matchAll(/\bwith\s+(?:recursive\s+)?([A-Za-z_][A-Za-z0-9_$]*)\s+as\b/gi)) ctes.add(m[1].toLowerCase());
  for (const m of s.matchAll(/,\s*([A-Za-z_][A-Za-z0-9_$]*)\s+as\s*\(/gi)) ctes.add(m[1].toLowerCase());

  const byName = new Map();
  for (const r of relations) {
    const k = String(r.name ?? '').toLowerCase();
    if (!k) continue;
    if (!byName.has(k)) byName.set(k, []);
    if (!byName.get(k).includes(r.schema)) byName.get(k).push(r.schema);
  }

  const out = [];
  const seen = new Set();
  for (const m of s.matchAll(/\b(?:from|join|into|update|table)\s+(?:only\s+)?([A-Za-z_][A-Za-z0-9_$]*)/gi)) {
    if (s[m.index + m[0].length] === '.') continue; // schema-qualified: resolves without the path
    const name = m[1].toLowerCase();
    if (ctes.has(name) || seen.has(name) || !byName.has(name)) continue;
    seen.add(name);
    out.push({ name: m[1], schemas: byName.get(name) });
  }
  return out;
}

/**
 * The declared parameters of a function, name **and** type.
 *
 * The type is load-bearing for the `format()` check below: `%s` does no escaping,
 * but an `integer` or `uuid` argument cannot carry SQL through it no matter what
 * the caller sends — the value is rendered by the type's output function, and
 * `'1; drop table x'::int` never reaches `format()` at all. Flagging those was
 * the false positive fixed here.
 *
 * `parameterNames` decides which tokens are names (it already knows `character
 * varying` is a type, not a name); this only adds the type text beside them.
 */
export function parameterSignature(args) {
  const named = new Set(parameterNames(args));
  const out = [];
  for (const raw of String(args || '').split(',')) {
    let toks = raw.trim().split(/\s+/).filter(Boolean);
    if (toks.length && /^(in|out|inout|variadic)$/i.test(toks[0])) toks = toks.slice(1);
    if (toks.length < 2 || !named.has(toks[0])) continue;
    out.push({ name: toks[0], type: toks.slice(1).join(' ').toLowerCase() });
  }
  return out;
}

/**
 * Types whose output representation cannot carry SQL. Measured the boring way:
 * every one of these is produced by a fixed output function over a value that had
 * to parse as that type first, so `format('%s', v)` yields digits, a canonical
 * uuid, or an ISO timestamp — nothing that can close a literal or start a new
 * statement. Anything NOT on this list (text, varchar, json, an array, a domain,
 * a type we couldn't parse) is treated as able to carry SQL, so an unknown type
 * still gets flagged rather than waved through.
 */
const SQL_INERT_TYPES = new Set([
  'smallint', 'integer', 'int', 'int2', 'int4', 'int8', 'bigint',
  'numeric', 'decimal', 'real', 'double precision', 'float', 'float4', 'float8', 'money',
  'boolean', 'bool', 'uuid', 'oid', 'date',
  'timestamp', 'timestamptz', 'timestamp without time zone', 'timestamp with time zone',
  'time', 'time without time zone', 'time with time zone', 'interval',
]);

export function canCarrySql(type) {
  if (!type) return true; // unknown => assume the worst
  const t = String(type).toLowerCase().replace(/\(.*$/, '').replace(/\s+/g, ' ').trim();
  if (t.endsWith('[]')) return true;
  return !SQL_INERT_TYPES.has(t);
}

/**
 * Split the top-level arguments of a call whose `(` sits at `open`.
 *
 * Needed because the specifier→argument mapping below has to be positional, and
 * naive comma-splitting mis-aligns on the first nested call: `format('… %L … %s',
 * coalesce(p_o, 'x'), 50)` splits into three pieces, so the `%s` lines up with
 * `'x'` instead of `50`. Tracks single-quoted literals (with `''` escapes),
 * double-quoted identifiers, dollar-quoted bodies (`$tag$…$tag$`, never `$1`),
 * and paren depth.
 *
 * @returns {{args:string[], end:number}|null} null when the text cannot be read.
 */
export function splitCallArgs(s, open) {
  if (s[open] !== '(') return null;
  const args = [];
  let depth = 0;
  let start = open + 1;
  let i = open;
  while (i < s.length) {
    const c = s[i];
    if (c === "'" || c === '"') {
      const q = c;
      i++;
      for (;;) {
        if (i >= s.length) return null; // unterminated literal: unreadable
        if (s[i] === q) { if (s[i + 1] === q) { i += 2; continue; } i++; break; }
        i++;
      }
      continue;
    }
    if (c === '$') {
      const tag = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(s.slice(i));
      if (tag) {
        const close = s.indexOf(tag[0], i + tag[0].length);
        if (close < 0) return null;
        i = close + tag[0].length;
        continue;
      }
      i++; // `$1` and friends are ordinary text
      continue;
    }
    if (c === '(') { depth++; i++; continue; }
    if (c === ')') {
      depth--;
      if (depth === 0) { args.push(s.slice(start, i)); return { args, end: i }; }
      i++;
      continue;
    }
    if (c === ',' && depth === 1) { args.push(s.slice(start, i)); start = i + 1; i++; continue; }
    i++;
  }
  return null; // ran off the end without closing
}

/**
 * Which specifier consumes each `format()` argument.
 *
 * `%s` at position 3 says nothing about the parameter at position 1 — that was
 * the bug: `format('… = %L limit %s', p_owner, 50)` was reported as injection
 * through `p_owner`, which is bound by `%L` and cannot be injected. Measured on
 * exactly that function: three payloads (`' or true --`, `%' or true --`,
 * `x%' union select …`) each returned zero rows, and the guard reported it as the
 * sole violation on the build.
 *
 * Postgres also supports explicit `%n$s` ordering, which defeats plain counting,
 * so positions are read rather than assumed. Anything unexpected (`%*s`, whose
 * width comes from an argument, or a position past the end of the list) returns
 * null: unreadable, which the caller reports as a note, never as a failure.
 *
 * @returns {Map<number, Set<'s'|'I'|'L'>>|null} 1-based argument position -> specifiers
 */
export function formatSpecifierMap(fmt, argCount) {
  const map = new Map();
  let next = 1;
  for (let i = 0; i < fmt.length; i++) {
    if (fmt[i] !== '%') continue;
    const m = /^%(?:(\d+)\$)?(-?)(\d*)([sIL%])/.exec(fmt.slice(i));
    if (!m) return null; // %*s, a stray %, or a type we don't model
    i += m[0].length - 1;
    if (m[4] === '%') continue; // a literal percent consumes no argument
    // An explicit position does NOT advance the sequential counter (Postgres docs).
    const pos = m[1] ? Number(m[1]) : next++;
    if (pos < 1 || pos > argCount) return null; // list doesn't line up
    if (!map.has(pos)) map.set(pos, new Set());
    map.get(pos).add(m[4]);
  }
  return map;
}

/** Every `format(<literal>, …)` call in a statement, arguments split out. */
function formatCalls(stmt) {
  const out = [];
  const re = /\bformat\s*\(/gi;
  let m;
  while ((m = re.exec(stmt))) {
    const open = m.index + m[0].length - 1;
    const split = splitCallArgs(stmt, open);
    if (!split || split.args.length === 0) { out.push({ readable: false }); continue; }
    const lit = /^'((?:[^']|'')*)'$/.exec(split.args[0].trim());
    // A non-literal format string (a variable holding the SQL) is not this
    // check's business — it falls through to the concatenation check, as before.
    if (lit) out.push({ readable: true, fmt: lit[1].replace(/''/g, "'"), args: split.args.slice(1) });
    re.lastIndex = split.end + 1;
  }
  return out;
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
 *   • it is the argument that `format()`'s **`%s`** consumes — positionally, not
 *     "there is a `%s` somewhere" — and its type can carry SQL.
 * `quote_literal()`, `quote_ident()`, `format('%L'/'%I')` and `EXECUTE … USING`
 * are all correct and produce no finding. Where the mapping cannot be read the
 * result is `format-unproven`, which the caller reports as a note: a skip is not
 * a pass, but it is not a build failure either.
 *
 * `params` accepts plain names (type unknown => assumed able to carry SQL) or
 * `{name, type}` from `parameterSignature`.
 *
 * @returns {{param:string, via:'concat'|'format-%s'|'format-unproven', snippet:string}|null}
 */
export function dynamicSqlInjection(body, params = []) {
  const s = String(body || '');
  const ps = params.map((p) => (typeof p === 'string' ? { name: p, type: null } : p)).filter((p) => p && p.name);
  if (!/\bexecute\b/i.test(s) || ps.length === 0) return null;
  // Each EXECUTE's SQL expression: everything up to USING / end of statement.
  const stmts = [...s.matchAll(/\bexecute\b([\s\S]*?)(?:\busing\b|;|$)/gi)].map((m) => m[1]);
  for (const stmt of stmts) {
    const calls = formatCalls(stmt);
    const snippet = stmt.trim().slice(0, 140);
    for (const p of ps) {
      const mentions = new RegExp(`\\b${p.name}\\b`);
      if (!mentions.test(stmt)) continue;
      // Correctly quoted => not a finding.
      if (new RegExp(`(quote_literal|quote_ident)\\s*\\(\\s*${p.name}\\b`, 'i').test(stmt)) continue;
      if (calls.length) {
        let verdict = 'absent';
        for (const call of calls) {
          if (!call.readable) { verdict = 'unproven'; continue; }
          const map = formatSpecifierMap(call.fmt, call.args.length);
          const inCall = call.args.some((a) => mentions.test(a));
          if (!inCall) continue;
          if (!map) { verdict = 'unproven'; continue; }
          const via = call.args.map((a, idx) => (mentions.test(a) ? map.get(idx + 1) : null));
          const hitS = via.some((set) => set && set.has('s'));
          const unmapped = via.some((set, idx) => mentions.test(call.args[idx]) && !set);
          if (hitS) { verdict = 'unsafe'; break; }
          if (unmapped) verdict = 'unproven';
          else if (verdict !== 'unproven') verdict = 'bound';
        }
        // `%s` on a type that cannot carry SQL (an int limit, a uuid) is not an
        // injection: the value is rendered by the type's output function.
        if (verdict === 'unsafe' && !canCarrySql(p.type)) continue;
        if (verdict === 'unsafe') return { param: p.name, via: 'format-%s', snippet };
        if (verdict === 'unproven') return { param: p.name, via: 'format-unproven', snippet };
        continue; // bound through %L/%I, or not passed to this format() at all
      }
      // Bare concatenation of the parameter into the SQL string.
      if (new RegExp(`\\|\\|[^;]*\\b${p.name}\\b|\\b${p.name}\\b[^;]*\\|\\|`).test(stmt)) {
        return { param: p.name, via: 'concat', snippet };
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
export function shadowableSchemas(config, writableSchemas = [], ownSchema = null) {
  const writable = new Set(writableSchemas);
  const path = searchPathSchemas(config);
  const out = [];

  // Where does the body's unqualified name actually resolve? The function's own
  // schema is the best available answer, and it is the one that matters: a
  // writable schema only helps an attacker if it comes BEFORE the schema that
  // really holds the object.
  //
  // Two things this has to get right at once.
  //
  //  * `pg_catalog` must not stop the walk. It holds system catalogs and none of
  //    your tables, so an unqualified name never resolves there. Stopping was a
  //    false negative: `pg_catalog, public, app` with `public` writable and the
  //    table in `app` reported nothing, and that path is hijackable — verified,
  //    the definer function ran a table planted in public.
  //
  //  * `public` on `pg_catalog, public` must NOT be reported when the function
  //    lives in public. Nothing precedes the real object, and an attacker cannot
  //    shadow a name in the same schema that already has it — the CREATE
  //    collides. Reporting it would fire on essentially every Supabase project,
  //    which is the cry-wolf outcome this tool is most damaged by.
  const target = String(ownSchema ?? '').toLowerCase();
  const stopAt = target
    ? path.findIndex((x) => x.toLowerCase() === target)
    : path.length - 1; // no better information: treat the last entry as the home
  const limit = stopAt < 0 ? path.length : stopAt;

  for (let i = 0; i < limit; i++) {
    const schema = path[i];
    if (schema.toLowerCase() === 'pg_catalog') continue;
    if (writable.has(schema)) out.push(schema);
    // A non-writable schema ahead of the target may itself hold the object, and
    // resolution stops at the first schema that has it, so nothing later can be
    // shadowed.
    else break;
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
 * That measurement was taken with the function and its table in the SAME schema,
 * and the conclusion drawn from it ("naming pg_temp last is the fix that is safe
 * to apply without also editing the body") only holds there. A pin replaces the
 * whole path, so it must name **every schema the body resolves unqualified names
 * in**, not just the schema the function lives in. Measured: a definer function
 * in `public` reading an unqualified `invoices` that lives in `app` worked
 * unpinned and raised `42P01 relation "invoices" does not exist` once pinned to
 * `pg_catalog, public, pg_temp` — which is what this guard used to emit.
 * `unqualifiedRelationRefs` is what stops it emitting that now.
 *
 * So: `pg_temp` last is necessary and does not by itself break a body whose
 * objects are all named in the pin; `search_path = ''` breaks any unqualified
 * body outright; and either way the function has to be run once afterwards,
 * because a pin that omits a schema fails at call time, not at ALTER time.
 */
export function temporarilyShadowable(config) {
  const schemas = searchPathSchemas(config);
  if (!schemas.length) return false; // unpinned: reported by the caller anyway
  return !schemas.some((x) => x.toLowerCase() === 'pg_temp');
}

/**
 * What we are willing to CALL — not what is guaranteed harmless. Postgres blocks
 * a direct write in a non-volatile body; it does not block that body from calling
 * a VOLATILE helper that writes, or from consuming a sequence. See the header.
 */
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

  // Where could the role plant a PERMANENT shadow on an unpinned search_path.
  // Not the precondition for the hijack as such — pg_temp needs no CREATE at all
  // (see tempGranted below) — but it is the precondition for the shape that
  // outlives the session, and it is what the failing branch is built on.
  let writableSchemas = [];
  try {
    const sc = schemaCreateSql(role);
    writableSchemas = (await q(sc.text, sc.values)).map((r) => r.schema);
  } catch { /* optional */ }

  // TEMP on the database, granted to PUBLIC by default. Measured with CREATE
  // revoked on every schema: `create temp table invoices(...)` still hijacked an
  // unpinned definer function. This is why the note below no longer says
  // "not exploitable".
  // null = the probe itself failed. Kept distinct from false so the note can say
  // "could not read this" instead of "there is nowhere to plant one".
  let tempGranted = null;
  try {
    const tc = tempCreateSql(role);
    const row = (await q(tc.text, tc.values))[0];
    tempGranted = row?.temp === true || row?.temp === 't';
  } catch { /* stays null */ }

  // Every relation in the scanned schemas, so the emitted ALTER can name the
  // schema the BODY resolves against rather than the one the function lives in.
  let relations = [];
  let relationsRead = false;
  try {
    const rs = relationsSql(cfg.schemas);
    relations = await q(rs.text, rs.values);
    relationsRead = true;
  } catch { /* the fix text falls back to fn.schema and says so */ }

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
        const inj = dynamicSqlInjection(fn.body, parameterSignature(fn.args));
        if (inj && inj.via === 'format-unproven') {
          // The parameter reaches a format() whose specifier-to-argument mapping
          // could not be read (a `%*s` width, a truncated literal, an argument
          // list that does not line up). Not proven safe, not proven unsafe — and
          // naming a specific parameter as injectable when it may be bound by %L
          // is the false accusation this branch exists to avoid.
          notes.push({
            where: fqn,
            message:
              `SECURITY DEFINER function building dynamic SQL with format(), and "${inj.param}" is one of the arguments. ` +
              `NOT PROVEN either way: tenant-guard could not map format()'s specifiers onto its arguments here, so it cannot tell whether "${inj.param}" is escaped by %L/%I or interpolated raw by %s. ` +
              `Injected SQL in a definer function runs as the OWNER and bypasses RLS, so check this one by hand. Near: ${inj.snippet}`,
          });
        } else if (inj) {
          violations.push({
            where: fqn,
            kind: 'sql-injection',
            message:
              `SQL INJECTION in a SECURITY DEFINER function: the "${inj.param}" argument is ${inj.via === 'concat' ? 'concatenated straight into' : 'the argument format() interpolates with %s into'} the SQL given to EXECUTE, and "${role}" may call it. ` +
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
        const shadowable = pinned ? shadowableSchemas(fn.config, writableSchemas, fn.schema) : [];
        const tempOpen = pinned && shadowable.length === 0 && temporarilyShadowable(fn.config);

        // Where the body's unqualified names actually resolve. The emitted ALTER
        // used to name fn.schema — where the FUNCTION lives — and a body reading
        // an unqualified table in another schema broke with 42P01 the moment the
        // fix was applied. fn.schema is kept in the path too (after the body's
        // schemas) so an unqualified call to a sibling helper still resolves.
        const unqualified = unqualifiedRelationRefs(fn.body, relations);
        const derivedPin = [];
        for (const r of unqualified) for (const sch of r.schemas) if (!derivedPin.includes(sch)) derivedPin.push(sch);
        if (!derivedPin.includes(fn.schema)) derivedPin.push(fn.schema);
        // A pin that is only missing pg_temp keeps its own schema list — that
        // list already resolves, and reordering it would be a second change the
        // user did not ask for. A pin that reaches a writable schema first, and
        // an absent pin, get the derived one.
        const existingPin = searchPathSchemas(fn.config).filter((s) => !/^(pg_catalog|pg_temp)$/i.test(s));
        const pinSchemas = tempOpen && existingPin.length ? existingPin : derivedPin;
        const pinPath = ['pg_catalog', ...pinSchemas, 'pg_temp'].join(', ');
        const writableInPin = pinSchemas.filter((s) => writableSchemas.includes(s));

        if ((!pinned && writableSchemas.length > 0) || shadowable.length > 0 || tempOpen) {
          violations.push({
            where: fqn,
            kind: 'search-path',
            message: tempOpen
              ? `SECURITY DEFINER function whose search_path is pinned, but does not name pg_temp — so the pin is incomplete. ` +
                `Postgres searches pg_temp BEFORE every schema you list unless you name it, and TEMP on the database is granted to PUBLIC by default, so any role that can open a session can create a temp table and shadow an unqualified name inside this function. It needs no CREATE privilege anywhere. ` +
                `Measured with CREATE ON SCHEMA public revoked: pinned "pg_catalog, ${pinSchemas[0]}" the function ran the attacker's temp table; with pg_temp named last it ran the real one.`
              : pinned
              ? `SECURITY DEFINER function whose search_path is pinned to ${shadowable.map((s) => `"${s}"`).join(', ')} — which "${role}" can CREATE objects in, so the pin protects nothing. ` +
                `Resolution walks the pinned path in order and reaches a schema they can plant in before it reaches yours, so an unqualified name in the body finds THEIR object, executing as the owner with RLS bypassed. ` +
                `Verified against a real database: a function pinned to a writable schema returned a planted table; the same function pinned to its own schema first returned the real one.`
              : `SECURITY DEFINER function with no pinned search_path, and "${role}" can CREATE objects in ${writableSchemas.slice(0, 3).map((s) => `"${s}"`).join(', ')}. ` +
                `Unqualified names inside the function resolve through the CALLER's search_path, so a caller who creates a table or function earlier on that path makes this function operate on THEIR object — executing as the definer's owner, with RLS bypassed.`,
            fix:
              `Pin it to a path nobody can plant on, naming every schema the body resolves unqualified names in, with pg_temp LAST:\n` +
              `        ALTER FUNCTION ${fn.schema}.${fn.name}(${fn.args || ''}) SET search_path = ${pinPath};\n` +
              (unqualified.length
                ? `      That path names ${pinSchemas.map((s) => `"${s}"`).join(', ')} because the body reads ${unqualified.slice(0, 4).map((r) => `"${r.name}"`).join(', ')} unqualified, and that is where those relations live — not necessarily "${fn.schema}", which is only where the FUNCTION lives. Pinning to the wrong schema does not fail the ALTER, it fails the next call with "relation does not exist".\n`
                : relationsRead
                ? `      This check found no unqualified relation reference it could resolve in the body, so "${fn.schema}" is the best available guess at where its objects live. If the body names objects in another schema (or builds names at runtime), add those schemas before pg_temp.\n`
                : `      The relation catalog could not be read, so this check could not work out which schemas the body resolves unqualified names in — "${fn.schema}" is a guess. Check the body before applying this, and add every schema it names before pg_temp.\n`) +
              `      Then CALL the function once. A pin that omits a schema the body needs breaks at call time, not at ALTER time.\n` +
              `      pg_temp is the part that gets left out. Postgres searches it BEFORE everything you list unless you name it, and TEMP is granted to PUBLIC by default — so without it the pin is defeated by a temp table, needing no CREATE privilege anywhere.\n` +
              `      Verified: pinned "pg_catalog, ${pinSchemas[0]}" the function ran a planted temp table; with pg_temp named last it ran the real one.\n` +
              (writableInPin.length
                ? `      "${role}" can CREATE in ${writableInPin.map((s) => `"${s}"`).join(', ')}, which that path names — REVOKE CREATE ON SCHEMA ${writableInPin.join(', ')} FROM ${role}; or the pin just fixes the attacker on the path they were already taking.\n`
                : '') +
              `      The strictest form is SET search_path = '' with every reference schema-qualified inside the body. Do NOT apply that one blindly: with an unqualified body the function stops working ("relation does not exist").`,
          });
        } else if (!pinned) {
          // NOT a safety claim. This used to read "Not exploitable here — cannot
          // CREATE objects in any schema, so nowhere to plant a shadowing object",
          // and that is false: measured on PG 18.3 with CREATE revoked on every
          // schema (has_schema_privilege returned the empty set), a plain
          // `create temp table invoices(...)` made an unpinned definer function
          // read the attacker's table. pg_temp is searched first and needs no
          // CREATE. It stays a note rather than a failure because whether the
          // shadow BUYS the attacker anything depends on what the body does with
          // the object — but the recommended DDL now names pg_temp, so applying
          // it does not turn the next run red on this same guard, which is what
          // the old advice did.
          notes.push({
            where: fqn,
            message:
              `SECURITY DEFINER function with no pinned search_path. "${role}" cannot CREATE in any schema, so it cannot plant a shadow that outlives its session` +
              (tempGranted === true
                ? ` — but that is not the whole precondition: pg_temp is searched BEFORE the entire search_path unless the function names it, and TEMP on this database is granted to "${role}" (the PUBLIC default), so a temp table shadows an unqualified name in the body with no CREATE privilege anywhere. ` +
                  (unqualified.length
                    ? `The body reads ${unqualified.slice(0, 3).map((r) => `"${r.name}"`).join(', ')} unqualified. `
                    : relationsRead
                    ? `This check found no unqualified relation reference in the body text; it cannot see names built at runtime in dynamic SQL. `
                    : `This check could not read the relation catalog, so it does not know whether the body names anything unqualified. `) +
                  `NOT REPORTED AS A FAILURE because whether the substituted object gains the caller anything depends on what the body does with it — read it, then pin it.`
                : tempGranted === false
                ? `, and TEMP on this database is revoked for it, so there is nowhere to plant one at all.`
                : `. This check could not read TEMP on the database, so it cannot say whether a temp table could shadow an unqualified name here — pg_temp is searched before everything and TEMP is granted to PUBLIC by default, so assume it can.`) +
              ` Pin it: ALTER FUNCTION ${fn.schema}.${fn.name}(${fn.args || ''}) SET search_path = ${pinPath}; then call the function once to confirm the path still resolves.`,
          });
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
      let measured = false;

      // Every probe gets its own savepoint. Without one, a single function whose
      // call errors — and the guard's own note below says that is the ORDINARY
      // case, a return shape with no tenant column — aborts this transaction, and
      // every function scanned afterwards fails with 25P02 and is downgraded to a
      // reassuring note. A proven leak then reports green, decided by nothing more
      // than alphabetical order. Reproduced, and fixed the way the six sibling
      // guards already do it.
      const sp = async (fnc) => {
        await query('savepoint tg_probe', []);
        try {
          const out = await fnc();
          await query('release savepoint tg_probe', []);
          return { ok: true, out };
        } catch (err) {
          try { await query('rollback to savepoint tg_probe', []); await query('release savepoint tg_probe', []); }
          catch { /* the outer rollback still discards everything */ }
          return { ok: false, err };
        }
      };

      if (call.mode === 'tenant-arg') {
        const p = tenantArgProbeSql(fn.schema, fn.name, call.argType);
        const r = await sp(async () => (await q(p.text, [tenantB]))[0].n);
        if (!r.ok) {
          if (!isPermissionDenied(r.err)) {
            notes.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, message: `not probed — calling it errored (${r.err.message.slice(0, 120)}). This is usually a return shape without a tenant column, not a leak.` });
          }
          continue;
        }
        foreignRows = r.out;
        measured = true;

        if (foreignRows > 0) {
          const c = await sp(async () => (await q(p.text, [sentinelFor(call.argType)]))[0].n);
          if (c.ok) controlRows = c.out;
          else {
            // The control arm only ever DOWNGRADES a finding (it reclassifies
            // "trusts-argument" as "no-filter"). Losing it must never lose the
            // leak that was already measured — that is what used to happen.
            notes.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, message: `the control probe could not run (${c.err.message.slice(0, 90)}), so the finding below is reported as trusts-argument; it may in fact ignore the argument entirely.` });
          }
        }
      } else {
        const p = noArgProbeSql(fn.schema, fn.name, tenantColumn);
        const r = await sp(async () => (await q(p.text, [tenantA]))[0].n);
        if (!r.ok) {
          if (!isPermissionDenied(r.err)) {
            notes.push({ where: `${fn.schema}.${fn.name}(${fn.args || ''})`, message: `not probed — calling it errored (${r.err.message.slice(0, 120)}). This is usually a return shape without a tenant column, not a leak.` });
          }
          continue;
        }
        foreignRows = r.out;
        measured = true;
      }
      if (!measured) continue;

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
