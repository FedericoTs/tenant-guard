/**
 * Guard: what your policies TRUST for identity.
 *
 * Every other runtime guard here asks "given a correct identity, is the data
 * scoped?". This one asks the prior question: **can the caller forge the identity
 * itself?** A perfectly-written `USING (org_id = <identity>)` is worthless if the
 * caller controls `<identity>`.
 *
 * Five findings, deliberately at different confidence levels — because they are
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
 *   4. **The policy's AUTHORITY is user-writable → FAIL.** The textbook policy
 *      `USING (org_id IN (SELECT org_id FROM memberships WHERE user_id = auth.uid()))`
 *      is flawless — and completely bypassable if the caller can write
 *      `memberships`: insert yourself a row for someone else's org and every
 *      policy trusting that table now returns their data, legitimately. The soft
 *      thing is one table away, which is why per-table checking never finds it.
 *      Dependencies come from `pg_depend` (exact), not from parsing policy text.
 *      The near-miss worth naming: `WITH CHECK (user_id = auth.uid())` pins WHO
 *      you are and leaves WHICH TENANT completely open.
 *
 *   5. **A column that grants access is writable on your OWN row → FAIL.** Same
 *      family as (4), but the write is an `UPDATE` of your own record and what
 *      permits it is a **column privilege**, not a policy: `CREATE POLICY self ON
 *      profiles FOR UPDATE USING (id = auth.uid()) WITH CHECK (id = auth.uid())`
 *      is exactly right and still the bug, because **RLS is ROW-level and cannot
 *      restrict columns**. It pins which rows you may touch and says nothing about
 *      which fields, so you can set your own `role` to `'admin'`, or re-parent your
 *      own `organization_id` into another tenant. Only a column-level GRANT stops
 *      it, so that is what is read (`has_column_privilege`) and what the fix says.
 *
 * Read-only: catalog reads plus, for the forgery proof, one rolled-back
 * transaction.
 */
import {
  quoteIdent,
  qualified,
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
  why: 'Asks the question every other check assumes away: can the caller forge the identity your policies authorize from? Flags user-writable JWT claims (user_metadata), callable SECURITY DEFINER functions that set the tenant GUC from an argument, membership tables that policies derive authority from but the caller can write (a self-grant into any tenant), and — the one people hit most — an admin flag a user can set on their OWN row: RLS is ROW-level, so a textbook-correct self-update policy pins which rows you may touch and says nothing about which columns, and only a column-level GRANT can.',
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  role: PROOF_DEFAULTS.role,
  becomeTenant: PROOF_DEFAULTS.becomeTenant,
  claim: null,
  // Columns that decide what a caller may SEE. If the app role can UPDATE one of
  // these on a table its own policies read, it escalates by editing its own row.
  authorizationColumns: ['role', 'roles', 'user_role', 'is_admin', 'is_superadmin', 'is_staff', 'is_owner', 'admin', 'permissions', 'scopes', 'access_level', 'plan', 'tier'],
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

/**
 * Does the body AUTHORIZE the argument before it trusts it?
 *
 * The `forgeable-guc` finding used to fire on any definer function that set the
 * trusted GUC from a parameter — including one that checks membership first,
 * which is verbatim what the finding's own fix text tells you to write. Applying
 * the recommended remediation left the guard failing you, which is a closed loop:
 * the only way out was to ignore the tool. Verified against a real database.
 *
 * The gate is looked for BEFORE the `set_config` call, because a check that runs
 * afterwards has already leaked the tenant. Recognising this is deliberately
 * loose: a false NOTE on a function that only looks authorized is much cheaper
 * than telling someone their correct code is a "become any tenant" primitive.
 */
export function authorizesBeforeSettingGuc(body, guc) {
  const text = String(body ?? '');
  const esc = String(guc ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const at = text.search(new RegExp(`set_config\\s*\\(\\s*'${esc}'`, 'i'));
  if (at < 0) return false;
  const before = text.slice(0, at);

  // Something that can REFUSE: raise, or a return that ends the function early.
  const refuses = /\braise\s+(exception|error)\b/i.test(before)
    || /\breturn\b[^;]*;/i.test(before);
  // Something that consults the VERIFIED identity, rather than the argument.
  const consultsIdentity = /auth\.uid\s*\(|request\.jwt|auth\.jwt\s*\(|current_setting\s*\(\s*'request\./i.test(before);
  // …and actually looks it up.
  const looksUp = /\b(select|exists|perform)\b/i.test(before);

  return refuses && consultsIdentity && looksUp;
}

/**
 * Which OTHER tables each tenant policy depends on — its "authority tables".
 * Read from `pg_depend` rather than by parsing the policy expression: creating a
 * policy records a real dependency on every relation its subqueries touch, so
 * this is exact where a regex over `pg_policies.qual` would be a guess.
 * The policy's own table is excluded (it always self-depends).
 */
export function authorityDepsSql(schemas) {
  const text = `
    select distinct
           n.nspname  as schema,
           pc.relname as policy_table,
           p.polname  as policy,
           dn.nspname as dep_schema,
           dc.relname as dep_table
    from pg_catalog.pg_depend d
    join pg_catalog.pg_policy p on p.oid = d.objid and d.classid = 'pg_policy'::regclass
    join pg_catalog.pg_class pc on pc.oid = p.polrelid
    join pg_catalog.pg_namespace n on n.oid = pc.relnamespace
    join pg_catalog.pg_class dc on dc.oid = d.refobjid and d.refclassid = 'pg_class'::regclass
    join pg_catalog.pg_namespace dn on dn.oid = dc.relnamespace
    where n.nspname = any($1)
      and dc.oid <> p.polrelid
      and dc.relkind in ('r', 'p', 'v', 'm')
    order by 1, 2, 3, 4, 5`;
  return { text, values: [schemas] };
}

/** RLS status, tenant column, and write grants for each authority table. */
export function authorityDetailSql(qualifiedNames, tenantColumns, role) {
  const text = `
    select n.nspname as schema,
           c.relname as table,
           c.relrowsecurity as rls_enabled,
           (select a.attname
              from pg_catalog.pg_attribute a
             where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
               and a.attname = any($2)
             order by array_position($2, a.attname)
             limit 1) as tenant_column,
           pg_catalog.has_table_privilege($3::text, c.oid, 'INSERT') as can_insert,
           pg_catalog.has_table_privilege($3::text, c.oid, 'UPDATE') as can_update
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where (n.nspname || '.' || c.relname) = any($1)`;
  return { text, values: [qualifiedNames, tenantColumns, role] };
}

/** The INSERT/UPDATE-applicable policies on the authority tables. */
export function writePoliciesSql(qualifiedNames) {
  const text = `
    select p.schemaname as schema,
           p.tablename  as table,
           p.policyname as policy,
           p.cmd        as cmd,
           p.qual       as qual,
           p.with_check as with_check
    from pg_catalog.pg_policies p
    where (p.schemaname || '.' || p.tablename) = any($1)
      and p.cmd in ('ALL', 'INSERT', 'UPDATE')`;
  return { text, values: [qualifiedNames] };
}

/**
 * The expression that actually gates a NEW row for a policy. `FOR INSERT` always
 * carries WITH CHECK; a `FOR ALL` policy with no explicit WITH CHECK reuses its
 * USING expression as the check.
 */
export function effectiveCheck(policy) {
  // Postgres reuses USING as the WITH CHECK when none is given — for UPDATE as
  // well as ALL, not just ALL. Verified: an UPDATE policy with USING only raises
  // 42501 "new row violates row-level security policy" on a tenant hop, so the
  // USING clause IS the check. Treating that as "no check" read a correctly
  // constrained policy as unconstrained.
  const inheritsUsing = policy.cmd === 'ALL' || policy.cmd === 'UPDATE';
  return policy.with_check ?? (inheritsUsing ? policy.qual : null);
}

/**
 * Verdict for one authority table: can the caller write themselves into another
 * tenant's data by writing the table that DECIDES their access?
 *
 * The severity is that this is not a leak in the protected table's policy at all
 * — that policy can be flawless. The authority is what's soft.
 *
 * @returns {{status:'leak'|'safe'|'unknown', message?:string}}
 */
export function classifyAuthority({ schema, table, tenantColumn, rlsEnabled, canInsert, canUpdate, writePolicies = [], dependents = [], role = 'authenticated' }) {
  if (!canInsert && !canUpdate) return { status: 'safe' };
  if (!tenantColumn) {
    return { status: 'unknown', message: `policies on ${dependents.join(', ')} derive their authority from ${schema}.${table}, which "${role}" can write — but it has no recognised tenant column, so this check can't reason about whether a self-grant is possible. Confirm by hand that a user cannot insert or update a row here that widens their own access.` };
  }
  const writable = [];
  if (!rlsEnabled) {
    return {
      status: 'leak',
      message: `RLS is OFF on ${schema}.${table} and "${role}" holds a write grant on it — so a user can simply INSERT a row granting themselves membership of ANY tenant, and then read that tenant's data through a policy that is otherwise written correctly`,
    };
  }
  for (const cmd of ['INSERT', 'UPDATE']) {
    if (cmd === 'INSERT' && !canInsert) continue;
    if (cmd === 'UPDATE' && !canUpdate) continue;
    const applicable = writePolicies.filter((p) => p.cmd === cmd || p.cmd === 'ALL');
    if (applicable.length === 0) continue; // RLS on with no covering policy => denied
    // Any policy whose check never mentions the tenant column lets the caller
    // choose the tenant. `user_id = auth.uid()` is the classic near-miss: it pins
    // WHO you are and leaves WHICH ORG entirely open.
    const unconstrained = applicable.filter((p) => {
      const expr = effectiveCheck(p);
      return !expr || !new RegExp(`\\b${tenantColumn}\\b`, 'i').test(expr);
    });
    if (unconstrained.length > 0) writable.push({ cmd, policies: unconstrained.map((p) => p.policy) });
  }
  if (writable.length === 0) return { status: 'safe' };
  const parts = writable.map((w) => `${w.cmd} (policy ${w.policies.map((n) => `"${n}"`).join(', ')})`);
  return {
    status: 'leak',
    message: `"${role}" can ${parts.join(' and ')} on ${schema}.${table} under a policy that never constrains "${tenantColumn}" — so a user can write themselves a row for ANY tenant and then legitimately read that tenant's data through the policies that trust this table. A check like user_id = auth.uid() pins WHO you are but leaves WHICH TENANT wide open`,
  };
}

/**
 * Columns on an authority table that decide what the caller may see, with whether
 * the app role may UPDATE each ONE specifically.
 *
 * The reason this is a *column* question: **RLS is row-level and cannot restrict
 * columns.** The textbook-correct self-update policy —
 * `USING (id = auth.uid()) WITH CHECK (id = auth.uid())` — governs *which rows*
 * you may touch and says nothing about *which fields*, so it happily lets you
 * rewrite every column of your own row, `role` and `organization_id` included.
 * The only thing that stops that is a column-level GRANT, which is why this is
 * read from `has_column_privilege` rather than inferred from the policy text.
 */
/**
 * Every policy in the target schemas, whatever the table looks like.
 *
 * Distinct from `policyExprSql`, which is scoped to tables carrying a tenant
 * column — the right filter for tenant questions, and the wrong one here: a
 * `profiles` table usually has no tenant column at all, and it is exactly where
 * self-escalation lives.
 */
export function allPoliciesSql(schemas) {
  return {
    text: `
      select p.schemaname as schema,
             p.tablename  as table,
             p.policyname as policy,
             p.cmd        as cmd,
             p.qual       as qual,
             p.with_check as with_check
      from pg_catalog.pg_policies p
      where p.schemaname = any($1)`,
    values: [schemas],
  };
}

export function escalationColumnsSql(qualifiedNames, columns, role) {
  const text = `
    select n.nspname as schema,
           c.relname as table,
           a.attname as column,
           pg_catalog.has_column_privilege($3::text, c.oid, a.attnum, 'UPDATE') as can_update_col
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    where (n.nspname || '.' || c.relname) = any($1)
      and a.attname = any($2)
    order by 1, 2, 3`;
  return { text, values: [qualifiedNames, columns, role] };
}

/**
 * Verdict for one authority table's self-escalation surface: can the caller
 * UPDATE a column on their OWN row that other policies authorize from?
 *
 * A tenant column always counts — re-parenting your row into another tenant is
 * escalation by definition. Any other column counts only when a policy that
 * depends on this table actually reads it, which is what makes the write matter.
 *
 * @returns {{status:'leak'|'safe', message?:string, columns?:string[]}}
 */
export function classifySelfEscalation({ schema, table, columns = [], updatePolicies = [], referencedColumns = [], role = 'authenticated' }) {
  // No UPDATE-applicable policy => the role cannot update any row here at all.
  if (updatePolicies.length === 0) return { status: 'safe' };
  const referenced = new Set(referencedColumns.map((c) => c.toLowerCase()));
  const writable = columns.filter((c) => c.canUpdate);

  // Conclusive: the DATABASE authorizes from this column, or the column IS the
  // tenant — rewriting it re-parents the row by definition.
  const authorized = writable.filter((c) => c.isTenant || referenced.has(c.name.toLowerCase()));
  // Named like an authorization field, but no policy reads it. The database does
  // not treat it as a boundary; the application almost certainly does, and SQL
  // cannot see that — so it is a note, in the same spirit as every other
  // "depends on architecture this cannot observe" finding here.
  const declaredOnly = writable.filter((c) => !c.isTenant && !referenced.has(c.name.toLowerCase()));

  const rowLevel =
    `RLS is ROW-level: a correct-looking self-update policy like USING (id = auth.uid()) WITH CHECK (id = auth.uid()) ` +
    `controls WHICH ROWS you may touch and says nothing about WHICH COLUMNS, so it does not stop this`;

  if (authorized.length > 0) {
    const names = authorized.map((c) => c.name);
    const why = authorized
      .map((c) => (c.isTenant ? `"${c.name}" re-parents the row into another tenant` : `"${c.name}" is read by a policy to decide access`))
      .join('; ');
    return {
      status: 'leak',
      columns: names,
      message:
        `"${role}" may UPDATE ${names.map((n) => `"${n}"`).join(', ')} on ${schema}.${table}, and a policy lets it update its OWN row — so a user escalates by rewriting their own record (${why}). ` +
        rowLevel,
    };
  }

  if (declaredOnly.length > 0) {
    const names = declaredOnly.map((c) => c.name);
    return {
      status: 'note',
      columns: names,
      message:
        `"${role}" may UPDATE ${names.map((n) => `"${n}"`).join(', ')} on ${schema}.${table}, on its OWN row. ` +
        `No policy authorizes from ${names.length === 1 ? 'it' : 'them'}, so the database does not treat ${names.length === 1 ? 'it' : 'them'} as a boundary — ` +
        `but the name says your application does, and if it does, a user grants themselves whatever it controls by updating their own profile. ` +
        rowLevel,
    };
  }

  return { status: 'safe' };
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
  const rawPolicyText = await q(pe.text, pe.values);
  const policies = rawPolicyText
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
      // A function that authorizes the argument against the verified session
      // before setting the GUC is the SHAPE THIS GUARD RECOMMENDS. Reporting it
      // meant the recommended fix could not clear the finding.
      if (hit.fromParam && authorizesBeforeSettingGuc(fn.body, hit.guc)) {
        notes.push({
          where: fqn,
          message:
            `SECURITY DEFINER function sets '${hit.guc}' from a caller argument, but authorizes that argument against the verified session first (a membership lookup and a raise ahead of the set_config). That is the recommended shape, so it is not reported as a leak — confirm the check really covers every path through the function, because everything downstream trusts this GUC.`,
        });
      } else if (hit.fromParam) {
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

  // ── 4. authority tables: can you WRITE the table that decides your access? ──
  const ad = authorityDepsSql(cfg.schemas);
  const deps = await q(ad.text, ad.values);
  const depNames = [...new Set(deps.map((d) => `${d.dep_schema}.${d.dep_table}`))].filter((n) => !skip.has(n));
  if (depNames.length > 0) {
    const det = authorityDetailSql(depNames, cfg.tenantColumns, role);
    const details = await q(det.text, det.values);
    const wp = writePoliciesSql(depNames);
    const writePolicies = await q(wp.text, wp.values);
    // Which escalation columns each authority table has and whether the role may
    // UPDATE them, plus which of those column NAMES the dependent policies
    // actually read — a writable column only escalates if something authorizes
    // from it.
    const ec = escalationColumnsSql(depNames, cfg.tenantColumns.concat(cfg.authorizationColumns), role);
    const escalationCols = {};
    for (const r of await q(ec.text, ec.values)) {
      const k = `${r.schema}.${r.table}`;
      (escalationCols[k] = escalationCols[k] || []).push(r);
    }
    const referencedByPolicy = {};
    for (const dep of deps) {
      const k = `${dep.dep_schema}.${dep.dep_table}`;
      const raw = rawPolicyText
        .filter((p) => p.schema === dep.schema && p.table === dep.policy_table && p.policy === dep.policy)
        .map((p) => `${p.qual || ''} ${p.with_check || ''}`)
        .join(' ');
      const hits = (escalationCols[k] || [])
        .map((c) => c.column)
        .filter((n) => new RegExp(`\\b${n}\\b`, 'i').test(raw));
      referencedByPolicy[k] = [...new Set((referencedByPolicy[k] || []).concat(hits))];
    }

    for (const d of details) {
      const id = `${d.schema}.${d.table}`;
      const dependents = [...new Set(deps.filter((x) => `${x.dep_schema}.${x.dep_table}` === id).map((x) => `${x.schema}.${x.policy_table}`))];
      const verdict = classifyAuthority({
        schema: d.schema,
        table: d.table,
        tenantColumn: d.tenant_column,
        rlsEnabled: d.rls_enabled === true || d.rls_enabled === 't',
        canInsert: d.can_insert === true || d.can_insert === 't',
        canUpdate: d.can_update === true || d.can_update === 't',
        writePolicies: writePolicies.filter((p) => `${p.schema}.${p.table}` === id),
        dependents,
        role,
      });
      if (verdict.status === 'leak') {
        violations.push({
          where: id,
          kind: 'writable-authority',
          message: `${verdict.message}. Policies that depend on it: ${dependents.join(', ')}`,
          fix:
            `Lock down the table your policies derive authority from — it is as security-critical as the policies themselves:\n` +
            `        ALTER TABLE ${qualified(d.schema, d.table)} ENABLE ROW LEVEL SECURITY;\n` +
            `        CREATE POLICY no_self_grant ON ${qualified(d.schema, d.table)} FOR INSERT\n` +
            `          WITH CHECK (${quoteIdent(d.tenant_column || 'organization_id')} IN (/* tenants the caller ALREADY belongs to */));\n` +
            `      Memberships are usually best written only by a SECURITY DEFINER invite/accept flow, never directly by ${role}.`,
        });
      } else if (verdict.status === 'unknown') {
        notes.push({ where: id, message: verdict.message });
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

  // ── 3.8 — self-row escalation, over EVERY self-updatable table ─────
  //
  // This used to run only on tables reached through `pg_depend` — i.e. ones
  // whose rows another table's policy consults. That missed the commonest shape
  // of the bug by a mile: `profiles.is_admin`, read by a policy ON profiles, or
  // read by nothing in the database at all because the application checks it.
  // Neither creates a cross-table dependency, so neither was ever examined.
  //
  // The write is an UPDATE of your OWN row and what permits it is a COLUMN
  // privilege, not a policy: RLS cannot restrict columns, so a textbook-correct
  // self-update policy still lets you rewrite the field that grants your access.
  {
    const ap = allPoliciesSql(cfg.schemas);
    const allPolicies = await q(ap.text, ap.values);
    const selfUpdatable = [...new Set(
      allPolicies
        .filter((r) => r.cmd === 'UPDATE' || r.cmd === 'ALL')
        .map((r) => `${r.schema}.${r.table}`),
    )].filter((n) => !skip.has(n));

    if (selfUpdatable.length > 0) {
      const ec2 = escalationColumnsSql(selfUpdatable, cfg.tenantColumns.concat(cfg.authorizationColumns), role);
      const cols = {};
      for (const r of await q(ec2.text, ec2.values)) {
        (cols[`${r.schema}.${r.table}`] = cols[`${r.schema}.${r.table}`] || []).push(r);
      }
      // A column "is authorized from" when ANY policy in scope reads its name —
      // including a policy on the table itself, which is the case the old
      // dependency-only lookup could not see.
      const allPolicyText = allPolicies.map((r) => `${r.qual || ''} ${r.with_check || ''}`).join(' ');

      for (const id of selfUpdatable) {
        const [schema, table] = [id.slice(0, id.indexOf('.')), id.slice(id.indexOf('.') + 1)];
        const esc = classifySelfEscalation({
          schema,
          table,
          columns: (cols[id] || []).map((c) => ({
            name: c.column,
            canUpdate: c.can_update_col === true || c.can_update_col === 't',
            isTenant: cfg.tenantColumns.includes(c.column),
          })),
          updatePolicies: allPolicies.filter((r) => `${r.schema}.${r.table}` === id && (r.cmd === 'UPDATE' || r.cmd === 'ALL')),
          referencedColumns: (cols[id] || [])
            .map((c) => c.column)
            .filter((n) => new RegExp(`\\b${n}\\b`, 'i').test(allPolicyText)),
          role,
        });
        if (esc.status === 'safe') continue;

        const fix =
          `RLS cannot fix this — use COLUMN-level privileges so the authorization fields simply aren't writable:\n` +
          `        REVOKE UPDATE ON ${qualified(schema, table)} FROM ${role};\n` +
          `        GRANT UPDATE (/* only the safe profile columns: display_name, avatar_url, … */) ON ${qualified(schema, table)} TO ${role};\n` +
          `      Change ${esc.columns.map((c) => `"${c}"`).join(', ')} only through a SECURITY DEFINER flow that authorizes the change.`;

        if (esc.status === 'leak') {
          violations.push({ where: id, kind: 'self-escalation', message: esc.message, fix });
        } else {
          notes.push({ where: id, message: `${esc.message}. ${fix.split('\n')[0]}` });
        }
      }
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
