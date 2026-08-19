/**
 * Guard: what your policies TRUST for identity.
 *
 * Every other runtime guard here asks "given a correct identity, is the data
 * scoped?". This one asks the prior question: **can the caller forge the identity
 * itself?** A perfectly-written `USING (org_id = <identity>)` is worthless if the
 * caller controls `<identity>`.
 *
 * Three findings, deliberately at different confidence levels — because they are
 * knowable to different degrees from SQL alone:
 *
 *   1. **`user_metadata` used for authorization → FAIL.** In Supabase,
 *      `user_metadata` is writable BY THE USER (`supabase.auth.updateUser({data})`)
 *      while `app_metadata` is not. A policy reading `auth.jwt() -> 'user_metadata'
 *      ->> 'org_id'` lets any user rewrite their own tenant and walk into anyone
 *      else's. There is no safe use of it as an authorization key, so finding it
 *      in the policy text is already conclusive — and we then *prove* it by
 *      forging exactly that claim and re-reading the victim's rows.
 *
 *   2. **A `SECURITY DEFINER` function that sets the GUC your policies trust,
 *      from one of its own arguments, and that your app role may EXECUTE → FAIL.**
 *      That is a callable "become any tenant" primitive. This is the concrete,
 *      provable form of "the identity GUC is forgeable".
 *
 *   3. **Policies authorizing from a client-settable custom GUC → NOTE, never a
 *      failure.** `current_setting('app.tenant')` is `USERSET`: anyone who can run
 *      SQL on that connection can set it. But whether that is a *vulnerability*
 *      depends on architecture SQL cannot see — if a trusted server sets it from a
 *      verified session and the client never gets a SQL channel, it is fine. (It
 *      is also exactly how this tool impersonates.) So we surface the dependency
 *      and what to check, and we do not fail the build on it. Claiming otherwise
 *      would be the kind of unfalsifiable finding this project exists to avoid.
 *
 * Read-only: catalog reads plus, for the forgery proof, one rolled-back
 * transaction.
 */
import {
  safeRole,
  isPermissionDenied,
  distinctTenantsSql,
  tenantRowCountSql,
  introspectionSql,
  planTables,
  applyClaimShortcut,
  DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';

export const meta = {
  id: 'identity-trust',
  title: 'What your policies trust for identity (forgeable-identity escalation)',
  why: 'Asks the question every other check assumes away: can the caller forge the identity your policies authorize from? Flags user-writable JWT claims (user_metadata) used for authorization, and callable SECURITY DEFINER functions that set the tenant GUC from an argument — a "become any tenant" primitive.',
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  role: PROOF_DEFAULTS.role,
  becomeTenant: PROOF_DEFAULTS.becomeTenant,
  claim: null,
  allowlist: [], // "schema.policyname", "schema.table", or "schema.function"
};

/** A tenant id that cannot exist — the control arm of the forgery probe. */
export const NONEXISTENT_TENANT = '__tenant_guard_no_such_tenant__';

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Policies on tables that carry a tenant column, with their expressions. */
export function policyExprSql(schemas, tenantColumns) {
  const text = `
    select p.schemaname as schema,
           p.tablename  as table,
           p.policyname as policy,
           p.cmd        as cmd,
           p.qual       as qual,
           p.with_check as with_check
    from pg_catalog.pg_policies p
    where p.schemaname = any($1)
      and exists (
        select 1
        from pg_catalog.pg_class c
        join pg_catalog.pg_namespace n on n.oid = c.relnamespace
        join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
        where n.nspname = p.schemaname and c.relname = p.tablename and a.attname = any($2)
      )
    order by p.schemaname, p.tablename, p.policyname`;
  return { text, values: [schemas, tenantColumns] };
}

/**
 * Classify what one policy expression trusts for identity.
 * `settableGucs` deliberately EXCLUDES `request.jwt.*`: those are populated by
 * PostgREST from a signature-verified token, so they are not client-settable in
 * the architecture that uses them.
 */
export function classifyIdentitySource(expr) {
  const s = expr || '';
  const settableGucs = [];
  for (const m of s.matchAll(/current_setting\s*\(\s*'([^']+)'/gi)) {
    const guc = m[1];
    if (/^request\.jwt\./i.test(guc)) continue;
    if (!settableGucs.includes(guc)) settableGucs.push(guc);
  }
  return {
    // Supabase exposes the same user-writable blob under two names.
    usesUserMetadata: /user_metadata|raw_user_meta_data/i.test(s),
    usesAppMetadata: /app_metadata|raw_app_meta_data/i.test(s),
    usesJwt: /request\.jwt\.|auth\.jwt\s*\(|auth\.uid\s*\(|auth\.role\s*\(/i.test(s),
    settableGucs,
  };
}

/** Merge the qual and with_check verdicts for one policy row. */
export function classifyPolicyRow(row) {
  const a = classifyIdentitySource(row.qual);
  const b = classifyIdentitySource(row.with_check);
  return {
    schema: row.schema,
    table: row.table,
    policy: row.policy,
    cmd: row.cmd,
    id: `${row.schema}.${row.table}`,
    usesUserMetadata: a.usesUserMetadata || b.usesUserMetadata,
    usesAppMetadata: a.usesAppMetadata || b.usesAppMetadata,
    usesJwt: a.usesJwt || b.usesJwt,
    settableGucs: [...new Set([...a.settableGucs, ...b.settableGucs])],
  };
}

/** SECURITY DEFINER functions in `schemas`, with body + EXECUTE grant for `role`. */
export function definerFunctionsSql(schemas, role) {
  const text = `
    select n.nspname as schema,
           p.proname as name,
           pg_catalog.pg_get_function_identity_arguments(p.oid) as args,
           p.prosrc  as body,
           pg_catalog.has_function_privilege($2, p.oid, 'EXECUTE') as can_execute
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where p.prosecdef
      and n.nspname = any($1)
    order by n.nspname, p.proname`;
  return { text, values: [schemas, role] };
}

// First words of Postgres types, so an UNNAMED argument (`text`) or a multi-word
// type (`character varying`) is never mistaken for a parameter name.
const TYPE_WORDS = new Set([
  'text', 'varchar', 'character', 'char', 'integer', 'int', 'int2', 'int4', 'int8', 'bigint',
  'smallint', 'boolean', 'bool', 'uuid', 'json', 'jsonb', 'numeric', 'decimal', 'real', 'double',
  'float', 'float4', 'float8', 'date', 'timestamp', 'timestamptz', 'time', 'timetz', 'interval',
  'bytea', 'money', 'inet', 'cidr', 'macaddr', 'xml', 'tsvector', 'tsquery', 'bit', 'serial',
  'bigserial', 'record', 'anyelement', 'anyarray', 'void',
]);

/**
 * Parameter NAMES declared by a function, from pg_get_function_identity_arguments.
 * The format is `name type` when named and bare `type` when not, so an entry that
 * reduces to a single token — or whose first token is a type word — has no name.
 * Unnamed parameters are still reachable as `$n`, which the caller matches separately.
 */
export function parameterNames(args) {
  if (!args) return [];
  return args
    .split(',')
    .map((raw) => {
      let toks = raw.trim().split(/\s+/).filter(Boolean);
      if (toks.length && /^(in|out|inout|variadic)$/i.test(toks[0])) toks = toks.slice(1);
      if (toks.length < 2) return null; // bare type => unnamed
      const first = toks[0].replace(/\[\]$/, '').toLowerCase();
      if (TYPE_WORDS.has(first)) return null; // e.g. "character varying"
      return /^[A-Za-z_][A-Za-z0-9_]*$/.test(toks[0]) ? toks[0] : null;
    })
    .filter(Boolean);
}

/**
 * Does this function body call `set_config` on one of `gucs` using a value the
 * CALLER supplies (a declared parameter, or a positional `$n`)? That is the whole
 * difference between "derives the tenant from the verified session" (fine) and
 * "become whatever tenant you ask for" (a callable escalation primitive).
 */
export function definerSetsTrustedGuc(body, args, gucs) {
  if (!body || !gucs || gucs.length === 0) return null;
  const params = parameterNames(args);
  for (const guc of gucs) {
    const esc = guc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`set_config\\s*\\(\\s*'${esc}'\\s*,([^)]*)\\)`, 'i');
    const m = String(body).match(re);
    if (!m) continue;
    const valueExpr = m[1];
    const fromParam = /\$\d+/.test(valueExpr) || params.some((p) => new RegExp(`\\b${p}\\b`).test(valueExpr));
    return { guc, fromParam, valueExpr: valueExpr.trim() };
  }
  return null;
}

/** The forged-claim statement: the tenant key ONLY inside user_metadata. */
export function forgeUserMetadataSql(claimKey) {
  if (!/^[A-Za-z0-9_]+$/.test(claimKey || '')) throw new Error(`unsafe claim key: ${JSON.stringify(claimKey)}`);
  return `select set_config('request.jwt.claims', json_build_object('user_metadata', json_build_object('${claimKey}', $1::text))::text, true)`;
}

/**
 * Which claim key the app's identity hinges on, so the forgery probe targets the
 * right one: an explicit `claim`, else the key inside a `json_build_object('<key>',
 * …)` becomeTenant template, else the tenant column itself.
 */
export function deriveClaimKey(cfg, tenantColumn) {
  if (cfg.claim) return typeof cfg.claim === 'string' ? cfg.claim : cfg.claim.key;
  for (const t of cfg.becomeTenant || []) {
    const m = String(t).match(/json_build_object\s*\(\s*'([^']+)'/i);
    if (m) return m[1];
  }
  return tenantColumn;
}

const USER_METADATA_FIX = (key) =>
  `Authorize from a source the user cannot write:\n` +
  `        USING (${key} = (auth.jwt() -> 'app_metadata' ->> '${key}'))   -- app_metadata is server-controlled\n` +
  `      or, better, from a memberships table keyed on auth.uid(). Never user_metadata / raw_user_meta_data.`;

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = applyClaimShortcut({ ...DEFAULTS, ...config }, config);
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;
  const skip = new Set(cfg.allowlist);

  const pe = policyExprSql(cfg.schemas, cfg.tenantColumns);
  const policies = (await q(pe.text, pe.values))
    .map(classifyPolicyRow)
    .filter((p) => !skip.has(`${p.schema}.${p.policy}`) && !skip.has(p.id) && !skip.has(p.policy));
  if (policies.length === 0) {
    return OK({ skipped: true, reason: `no policies on tenant-column tables in ${cfg.schemas.join(', ')}`, summary: 'skipped — no tenant policies' });
  }

  const violations = [];
  const notes = [];
  const umPolicies = policies.filter((p) => p.usesUserMetadata);
  const umTables = [...new Set(umPolicies.map((p) => p.id))];

  // ── 2. a callable definer function that sets a policy-trusted GUC ──
  const trustedGucs = [...new Set(policies.flatMap((p) => p.settableGucs))];
  if (trustedGucs.length > 0) {
    const df = definerFunctionsSql(cfg.schemas, role);
    for (const fn of await q(df.text, df.values)) {
      if (skip.has(`${fn.schema}.${fn.name}`)) continue;
      const canExecute = fn.can_execute === true || fn.can_execute === 't';
      const hit = definerSetsTrustedGuc(fn.body, fn.args, trustedGucs);
      if (!hit || !canExecute) continue;
      const fqn = `${fn.schema}.${fn.name}(${fn.args || ''})`;
      if (hit.fromParam) {
        violations.push({
          where: fqn,
          kind: 'forgeable-guc',
          message: `"${role}" may EXECUTE this SECURITY DEFINER function, and it sets '${hit.guc}' — the GUC your policies authorize from — to a value the CALLER passes in. That is a callable "become any tenant" primitive: call it with another tenant's id and every policy keyed on '${hit.guc}' then returns that tenant's rows.`,
          fix:
            `Derive the tenant inside the function from the verified session (auth.uid() / request.jwt.claims), never from an argument. If the argument is genuinely needed, authorize it first:\n` +
            `        if not exists (select 1 from memberships where user_id = auth.uid() and org_id = <arg>) then raise exception 'forbidden'; end if;\n` +
            `      Or: REVOKE EXECUTE ON FUNCTION ${fqn} FROM ${role};`,
        });
      } else {
        notes.push({ where: fqn, message: `SECURITY DEFINER function sets '${hit.guc}' (a GUC your policies authorize from) but not from a caller argument — looks intentional; confirm the value derives from the verified session.` });
      }
    }
  }

  // ── the forgery proof for (1) ──────────────────────────────────────
  let proven = false;
  if (umPolicies.length > 0) {
    const intro = introspectionSql(cfg.schemas, cfg.tenantColumns, role);
    const plan = planTables(await q(intro.text, intro.values), cfg.tenantColumns)
      .filter((t) => umTables.includes(`${t.schema}.${t.table}`));
    await query('begin', []);
    try {
      for (const t of plan) {
        const d = distinctTenantsSql(t.schema, t.table, t.tenantColumn, 2);
        const tenants = (await q(d.text, d.values)).map((r) => r.t);
        if (tenants.length < 2) continue;
        const victim = tenants[1];
        const claimKey = deriveClaimKey(cfg, t.tenantColumn);
        let forgeSql;
        try { forgeSql = forgeUserMetadataSql(claimKey); } catch { continue; }

        await query(`set local role ${role}`, []);
        const count = tenantRowCountSql(t.schema, t.table, t.tenantColumn, victim);
        try {
          // Control arm: forge a tenant that cannot exist. Anything visible here
          // is visible to everyone, so it is NOT evidence about user_metadata.
          await query(forgeSql, [NONEXISTENT_TENANT]);
          const baseline = (await q(count.text, count.values))[0].n;
          // Test arm: forge the victim's id and re-read.
          await query(forgeSql, [victim]);
          const forged = (await q(count.text, count.values))[0].n;
          if (forged > baseline) {
            proven = true;
            violations.push({
              where: `${t.schema}.${t.table}`,
              kind: 'user-metadata',
              message: `PROVEN by forgery: setting user_metadata.${claimKey} to another tenant's id granted ${forged - baseline} row(s) of that tenant's data. user_metadata is writable BY THE USER (supabase.auth.updateUser({ data: … })), so any user can do this to themselves and read any tenant.`,
              fix: USER_METADATA_FIX(claimKey),
            });
          }
        } catch (err) {
          if (!isPermissionDenied(err)) notes.push({ where: `${t.schema}.${t.table}`, message: `could not run the claim-forgery probe: ${err.message}` });
        }
        await query('reset role', []);
      }
    } finally {
      try { await query('rollback', []); } catch { /* ignore */ }
    }
  }

  // ── 1. policy-text findings, for anything the probe didn't prove ───
  for (const p of umPolicies) {
    if (violations.some((v) => v.kind === 'user-metadata' && v.where === p.id)) continue;
    const claimKey = deriveClaimKey(cfg, cfg.tenantColumns[0]);
    violations.push({
      where: `${p.id} (policy "${p.policy}")`,
      kind: 'user-metadata',
      message: `this policy authorizes from user_metadata, which is writable BY THE USER (supabase.auth.updateUser({ data: … })) — unlike app_metadata. Any user can rewrite their own tenant id and read another tenant's data. There is no safe use of user_metadata as an authorization key.`,
      fix: USER_METADATA_FIX(claimKey),
    });
  }

  // ── 3. settable-GUC dependence: an advisory, never a failure ───────
  for (const guc of trustedGucs) {
    const users = policies.filter((p) => p.settableGucs.includes(guc)).map((p) => `${p.id}."${p.policy}"`);
    notes.push({
      where: `current_setting('${guc}')`,
      message:
        `${users.length} policy/policies authorize from '${guc}', a client-settable (USERSET) GUC: ${users.slice(0, 3).join(', ')}${users.length > 3 ? `, +${users.length - 3} more` : ''}. ` +
        `That is safe ONLY if nothing user-controlled can reach SET/set_config on that connection — no callable SECURITY DEFINER function may set it from an argument (checked above), and clients must not be able to run arbitrary SQL. Policies keyed on request.jwt.claims are not exposed this way: PostgREST populates those from a signature-verified token.`,
    });
  }

  const scanned = policies.length;
  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length > 0
        ? `${violations.length} forgeable-identity issue(s) across ${scanned} tenant policy/policies` + (proven ? ' (one proven by claim forgery)' : '')
        : `${scanned} tenant policy/policies checked; identity sources look unforgeable` + (notes.length ? ` (${notes.length} note(s) — see below)` : ''),
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
