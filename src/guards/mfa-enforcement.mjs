/**
 * Guard: is your second factor actually a factor?
 *
 * MFA is enrolled in the auth service, the app asks for a code at sign-in, and
 * everyone believes the data is behind two factors. But PostgREST does not care
 * what your login screen did: it presents whatever JWT the client holds, and the
 * only thing that can refuse an `aal1` token at the data layer is a policy that
 * checks the assurance level.
 *
 * Two ways that goes wrong, and the first is the good one:
 *
 *   1. **The policy is PERMISSIVE.** Postgres ORs permissive policies together
 *      and ANDs restrictive ones. So `USING (auth.jwt()->>'aal' = 'aal2')`
 *      written the default way cannot restrict anything — it can only ADD access
 *      alongside your ordinary tenancy policy. Verified: with a permissive gate
 *      an `aal1` session reads every row it would have read anyway; with
 *      `AS RESTRICTIVE` it reads none. The policy reads exactly right and
 *      enforces nothing, which is the hardest kind of bug to see in review.
 *
 *   2. **No policy checks the level at all.** Factors are enrolled, the UI
 *      demands a code, and a token minted before the second factor — or lifted
 *      from a session — has the same data access as one that passed it. The
 *      second factor gates the screen, not the database.
 *
 * Catalog-only: policy definitions and factor counts. Nothing is executed, and
 * on a project with no `auth` schema it skips.
 */
import { safeRole, DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'mfa-enforcement',
  title: 'Whether MFA is enforced at the data layer or only at the login screen',
  why: "PostgREST honours whatever JWT the client presents, so the only thing that can refuse a single-factor token is a policy checking the assurance level. And an `aal2` check written PERMISSIVELY enforces nothing: Postgres ORs permissive policies, so it can only widen access — the policy reads correctly and does not restrict. Enrolled factors with no policy checking `aal` means MFA gates the screen, not the data.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  allowlist: [], // "schema.table" or "schema.policyname" exempt on purpose
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Every policy with the columns that decide whether it can restrict.
 *
 * `roles` is load-bearing and was not selected before this fix. Postgres only
 * ORs two permissive policies together for a session that BOTH of them apply to,
 * and a policy applies to a session only if its role is in that policy's roles.
 * Without `roles` the guard reported an `aal2` gate `TO authenticated` as
 * neutered by an unrelated `TO anon` policy. Measured on that exact schema:
 * authenticated/aal1 read 0 rows, authenticated/aal2 read 3 — the gate enforced
 * perfectly and the guard called it a leak.
 *
 * pg_policies renders a policy written with no `TO` clause as `{public}`, which
 * is the "applies to everyone" marker, not a role named public.
 */
export function policiesSql(schemas) {
  return {
    text: `
      select schemaname as schema,
             tablename  as table,
             policyname as policy,
             permissive as permissive,
             cmd        as cmd,
             roles      as roles,
             qual       as qual,
             with_check as with_check
      from pg_catalog.pg_policies
      where schemaname = any($1)
    `,
    values: [schemas],
  };
}

/**
 * Which roles can act AS each of the given roles.
 *
 * Needed because role names alone are not comparable. A policy `TO app_readers`
 * does apply to a session running as `authenticated` when `authenticated` is a
 * member of `app_readers` — measured: with the gate `TO authenticated` and the
 * other policy `TO app_readers`, aal1 read 1 row and aal2 read 1 row, i.e. the
 * gate really was neutered. A patch that compared role NAMES would have gone
 * silent on that and turned a true positive into a false negative.
 *
 * Superusers and BYPASSRLS roles are excluded: pg_has_role() reports them as
 * members of every role, so leaving them in would make every pair of role sets
 * "overlap" and undo the whole fix. They are also irrelevant here — RLS does not
 * apply to them at all.
 */
export function roleMembersSql(roleNames) {
  return {
    text: `
      select r.rolname as role, m.rolname as member
      from pg_catalog.pg_roles r
      join pg_catalog.pg_roles m
        on pg_catalog.pg_has_role(m.oid, r.oid, 'USAGE')
      where r.rolname = any($1)
        and not m.rolsuper
        and not m.rolbypassrls
    `,
    values: [roleNames],
  };
}

/** rows of {role, member} -> Map<role, Set<member>>. */
export function buildRoleMembers(rows) {
  const map = new Map();
  for (const r of rows ?? []) {
    if (!map.has(r.role)) map.set(r.role, new Set());
    map.get(r.role).add(r.member);
  }
  return map;
}

/**
 * Can one session have BOTH policies applied to it?
 *
 * `public` on either side means "every role", so it overlaps with anything.
 * Otherwise expand each role to the set of roles that can act as it and ask
 * whether those sets intersect — that is exactly the condition for some session
 * to sit under both policies at once.
 *
 * `members` absent (no catalog access) degrades to a plain name intersection.
 * That direction is deliberate: it can only make the guard quieter, never make
 * it report a gate that is actually enforcing.
 */
export function rolesOverlap(a, b, members) {
  const A = (a ?? []).map(String);
  const B = (b ?? []).map(String);
  if (A.length === 0 || B.length === 0) return true; // unknown — assume they meet
  if (A.includes('public') || B.includes('public')) return true;
  const expand = (names) => {
    const out = new Set();
    for (const n of names) {
      out.add(n);
      for (const m of members?.get(n) ?? []) out.add(m);
    }
    return out;
  };
  const ea = expand(A);
  for (const r of expand(B)) if (ea.has(r)) return true;
  return false;
}

/** Verified second factors, i.e. whether this project uses MFA at all. */
export function verifiedFactorsSql() {
  return {
    text: `select count(*)::int as n from auth.mfa_factors where status = 'verified'`,
    values: [],
  };
}

/** Tenant tables, so partial coverage can be named rather than guessed at. */
export function tenantTablesSql(schemas, tenantColumns) {
  return {
    text: `
      select distinct n.nspname as schema, c.relname as table
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_attribute a on a.attrelid = c.oid
      where c.relkind in ('r', 'p')
        and n.nspname = any($1)
        and a.attname = any($2)
        and a.attnum > 0 and not a.attisdropped
        and c.relrowsecurity
    `,
    values: [schemas, tenantColumns],
  };
}

/**
 * Does this expression consult the authenticator assurance level?
 *
 * Matches the claim by name rather than by any single spelling, since it is read
 * several ways — `auth.jwt()->>'aal'`, `request.jwt.claims`, or a helper whose
 * name mentions it — and all of those spell out `aal`.
 *
 * The old pattern used `\baal\b`, and `_` is a word character, so there was no
 * boundary between `is_` and `aal2`. Measured: `auth.is_aal2()`, `is_aal2()`,
 * `auth.require_aal2()`, `check_aal()` and `aal_at_least(2)` all returned false.
 * That is not harmless noise in one direction — with a permissive helper gate
 * the guard reported ok:true, scanned:0 and the note "no policy in the scanned
 * schemas checks the assurance level" while an aal1 session was measurably
 * reading every row; with a RESTRICTIVE helper gate it advised adding the policy
 * that was already there.
 *
 * So treat `_` as a separator instead of a word character, and require only that
 * `aal` is not glued to a letter or digit. Not `/aal[12]?\b/`: that fires on
 * ordinary columns — checked, it matches `totaal > 0`, `zaal_id`, `kraal` — and
 * a tenancy policy misread as an MFA gate is the false positive this guard is
 * most expensive to get wrong.
 *
 * Known blind spot, stated rather than papered over: a helper whose NAME does
 * not contain `aal` (`has_mfa()`, `require_second_factor()`) cannot be seen by
 * any regex over `qual`. Resolving pg_proc.prosrc would be needed for that; it
 * is not done, and the coverage note says so instead of claiming coverage.
 */
export function referencesAal(expr) {
  return /(?<![a-z0-9])aal[12]?(?![a-z0-9])/i.test(String(expr ?? ''));
}

/** `pg_policies.permissive` is the text PERMISSIVE / RESTRICTIVE. */
export function isPermissive(row) {
  return String(row?.permissive ?? 'PERMISSIVE').toUpperCase() !== 'RESTRICTIVE';
}

/**
 * Does another PERMISSIVE policy already grant the same rows for the same
 * command and role?
 *
 * This is the precondition the guard was missing, and without it the finding is
 * wrong on correct code. "A permissive policy cannot restrict" is only half the
 * rule; the accurate half is that it can only ever ADD access. If the aal2 gate
 * is the ONLY permissive policy on the table, then it is the sole grant, and an
 * aal1 session reads nothing — the policy enforces exactly what it looks like it
 * enforces. Verified:
 *
 *     aal2 gate + a tenancy policy   aal2 sees 1, aal1 sees 1   <- enforces nothing
 *     aal2 gate alone                aal2 sees 1, aal1 sees 0   <- enforces
 *
 * Reporting the second case would be telling someone to change a policy that is
 * already doing its job, which is the advice shape that caused an outage in
 * 0.26.0.
 *
 * "Same rows" means same command AND same roles. The role half was documented
 * here but never implemented, and the omission was not cosmetic. Measured on one
 * PGlite database, four tables, gate always `TO authenticated`:
 *
 *   other policy TO authenticated   aal1 1 row, aal2 1 row   neutered -> report
 *   other policy with no TO clause  aal1 1 row, aal2 1 row   neutered -> report
 *   other policy TO app_readers     aal1 1 row, aal2 1 row   neutered -> report
 *     (authenticated is a MEMBER of app_readers)
 *   other policy TO anon            aal1 0 rows, aal2 1 row  ENFORCES -> silent
 *
 * The old role-blind predicate reported all four. Applying its printed fix to
 * the fourth took authenticated/aal2 from 3 rows to 0: the DROP removed the only
 * permissive grant that role had, and a table with restrictive-only policies
 * denies everyone.
 */
export function hasOtherPermissiveGrant(gate, allPolicies, roleMembers) {
  const applies = (a, b) => a === 'ALL' || b === 'ALL' || a === b;
  return (allPolicies ?? []).some((p) =>
    p.schema === gate.schema &&
    p.table === gate.table &&
    p.policy !== gate.policy &&
    isPermissive(p) &&
    applies(String(p.cmd ?? 'ALL').toUpperCase(), String(gate.cmd ?? 'ALL').toUpperCase()) &&
    rolesOverlap(p.roles, gate.roles, roleMembers) &&
    !(referencesAal(p.qual) || referencesAal(p.with_check)));
}

/**
 * The policies that mention the assurance level, split by whether they can
 * enforce it. A permissive gate is only reported when something else already
 * grants the same rows to the same roles — see hasOtherPermissiveGrant.
 */
export function classifyAalPolicies(rows, roleMembers) {
  const all = rows ?? [];
  const gates = all.filter((r) => referencesAal(r.qual) || referencesAal(r.with_check));
  const permissive = gates.filter(isPermissive);
  return {
    permissive: permissive.filter((g) => hasOtherPermissiveGrant(g, all, roleMembers)),
    // A gate that is the only permissive grant for the roles it applies to IS
    // the grant, so it restricts. Tracked separately so the coverage note can
    // still count it as enforcement that exists.
    soleGrant: permissive.filter((g) => !hasOtherPermissiveGrant(g, all, roleMembers)),
    restrictive: gates.filter((r) => !isPermissive(r)),
  };
}

/**
 * `public` is the keyword meaning every role and must stay bare — `TO "public"`
 * names a role that does not exist and the statement errors. Everything else is
 * double-quoted so a role needing quoting still pastes and runs.
 */
export function quoteRole(name) {
  const s = String(name);
  return s === 'public' ? 'public' : `"${s.replace(/"/g, '""')}"`;
}

/**
 * The verdict for one permissive gate. Conclusive: this is Postgres semantics,
 * not a judgement about the application.
 *
 * The emitted DDL is rebuilt from the offending row, not from config. The old
 * template hardcoded `AS RESTRICTIVE FOR ALL TO <cfg.role>` and a made-up
 * `auth.jwt()` expression, and each of those three substitutions was measured
 * doing damage:
 *
 *   - `FOR ALL` on a `FOR SELECT` gate: after applying it, aal1 INSERT failed
 *     with "new row violates row-level security policy" and aal1 UPDATE became a
 *     silent 0-row no-op. Tightening writes may be what you want, but it must be
 *     a decision, not a side effect of pasting a fix.
 *   - `TO authenticated` on a gate whose roles were `{app_user}`: app_user/aal1
 *     still read 1 row — the leak was untouched — and the next run reported ok.
 *     The tool went green on a leak it had just proven.
 *   - `TO authenticated` on a gate written with no `TO` at all (roles
 *     `{public}`, the default Supabase shape): authenticated/aal1 went to 0 rows
 *     while anon/aal1 still read the row, and the guard went green.
 *   - the invented `auth.jwt()` expression does not exist outside Supabase.
 *     `row.qual` is the deparsed text of an expression that already runs on this
 *     database, so it is the one form guaranteed to paste cleanly.
 *
 * DROP+CREATE rather than adding a second policy: the permissive gate usually
 * over-grants as well as under-enforces — measured on the reference schema, the
 * permissive `using (aal = 'aal2')` gate let an aal2 session read all 3 rows
 * across both tenants, ignoring tenancy. Leaving it in place would keep that
 * open. Dropping it is safe here precisely because the finding's precondition is
 * that another permissive policy already grants these rows to these roles.
 */
export function classifyPermissiveGate({ row, role = 'authenticated' }) {
  const id = `${row.schema}.${row.table}`;
  const cmd = String(row.cmd ?? 'ALL').toUpperCase();
  const roles = (row.roles?.length ? row.roles : [role]).map(quoteRole).join(', ');

  // Reuse the policy's own expressions. A FOR INSERT policy has qual = null and
  // only a with_check, so emit whichever clauses the row actually has.
  const clauses = [];
  if (row.qual != null) clauses.push(`  USING (${row.qual})`);
  if (row.with_check != null) clauses.push(`  WITH CHECK (${row.with_check})`);
  if (clauses.length === 0) {
    // Nothing to copy — say so rather than emitting an expression this database
    // may not have. auth.jwt() only exists on Supabase.
    clauses.push(`  USING (<the policy's existing expression — this run could not read it>)`);
  }

  const caveats = [];
  if (cmd !== 'ALL') {
    caveats.push(
      `This keeps the gate's own command, ${cmd}: aal1 sessions can still run the other commands, exactly as today. ` +
      `To require the second factor for writes too, use FOR ALL instead — that blocks INSERT/UPDATE/DELETE for aal1 sessions, which the current policy does not.`);
  }
  if ((row.roles ?? []).includes('public')) {
    caveats.push(`The gate's role list is {public} (written with no TO clause), so the restrictive policy applies to every role including anon — which is the point, and is why it is kept rather than narrowed to ${role}.`);
  }

  return {
    status: 'leak',
    kind: 'permissive-mfa-gate',
    where: `${id} (policy "${row.policy}")`,
    message:
      `policy "${row.policy}" on ${id} checks the MFA assurance level but is PERMISSIVE, and another permissive policy on this table already grants the same rows to the same roles — so this one enforces nothing. ` +
      `Postgres ORs permissive policies together, so a permissive policy can only ever ADD access, never remove it. ` +
      `A session that never passed the second factor reads exactly what it would have read without this policy. ` +
      `Verified against a real database: with a tenancy policy alongside it, an aal1 session sees every row; with AS RESTRICTIVE it sees none. ` +
      `(A permissive aal2 policy that is the only permissive grant for the roles it covers is not reported — it is the sole grant, so it does restrict.)`,
    fix:
      `A gate has to be restrictive, because only restrictive policies are ANDed. ` +
      `This keeps the policy's own command and roles, so nothing that works today stops working:\n` +
      `        DROP POLICY "${row.policy}" ON ${id};\n` +
      `        CREATE POLICY "${row.policy}" ON ${id}\n` +
      `          AS RESTRICTIVE FOR ${cmd} TO ${roles}\n` +
      clauses.map((c) => `        ${c.trim()}`).join('\n') + `;\n` +
      (caveats.length ? `      ${caveats.join(' ')}\n` : '') +
      `      If this policy was meant to GRANT access to MFA'd users rather than gate everyone, ` +
      `add "${id}.${row.policy}" to mfaEnforcement.allowlist[] with that reason.`,
  };
}

/** The verdict for the project as a whole. */
export function classifyCoverage({ verifiedFactors = 0, gates, tenantTables = [], allow = new Set() }) {
  const notes = [];

  const sole = gates.soleGrant ?? [];
  if (gates.restrictive.length === 0 && gates.permissive.length === 0 && sole.length === 0) {
    if (verifiedFactors > 0) {
      notes.push({
        where: '(project)',
        message:
          `${verifiedFactors} verified MFA factor(s) are enrolled, but no policy in the scanned schemas visibly checks the assurance level ` +
          `(matched by reading the policy expressions for \`aal\`; a policy that delegates to a helper whose NAME does not mention aal — has_mfa(), require_second_factor() — cannot be seen from the catalog and is not covered by this statement). ` +
          `PostgREST honours whatever token the client presents, so a session that never completed the second factor has the same data access as one that did — ` +
          `MFA is gating your login screen, not your data. If that is deliberate (MFA for the admin console only, say), this is fine; if not, add an ` +
          `AS RESTRICTIVE policy requiring aal2 to the tables that matter.`,
      });
    }
    return notes;
  }

  // Some enforcement exists — so which tenant tables are left out of it?
  // A lone permissive gate restricts, so it counts as covered.
  const covered = new Set([...gates.restrictive, ...sole].map((r) => `${r.schema}.${r.table}`));
  const uncovered = tenantTables
    .map((t) => `${t.schema}.${t.table}`)
    .filter((id) => !covered.has(id) && !allow.has(id));

  if (covered.size > 0 && uncovered.length > 0) {
    notes.push({
      where: '(coverage)',
      message:
        `MFA is enforced by a restrictive policy on ${[...covered].slice(0, 3).join(', ')}${covered.size > 3 ? `, +${covered.size - 3} more` : ''}, ` +
        `but ${uncovered.length} other tenant table(s) have no such gate: ${uncovered.slice(0, 4).join(', ')}${uncovered.length > 4 ? ', …' : ''}. ` +
        `Partial enforcement is the shape people miss — the protected table is the one they thought of.`,
    });
  }
  return notes;
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const q = async (text, values) => (await query(text, values)).rows;
  const role = safeRole(cfg.role);
  const allow = new Set(cfg.allowlist);

  const pol = policiesSql(cfg.schemas);
  const policies = await q(pol.text, pol.values);

  // Resolve role membership before classifying: two policies only OR together
  // for a session that both apply to, and `TO app_readers` applies to a session
  // running as `authenticated` when authenticated is a member of app_readers.
  // Best-effort — if pg_roles is not readable, rolesOverlap falls back to a name
  // intersection, which can only make the guard quieter.
  let roleMembers;
  const roleNames = [...new Set(policies.flatMap((p) => p.roles ?? []).filter((r) => r !== 'public'))];
  if (roleNames.length) {
    try {
      const rm = roleMembersSql(roleNames);
      roleMembers = buildRoleMembers(await q(rm.text, rm.values));
    } catch { /* leave undefined */ }
  }

  const gates = classifyAalPolicies(policies, roleMembers);

  let verifiedFactors = 0;
  let hasAuthSchema = true;
  try {
    verifiedFactors = (await q(verifiedFactorsSql().text, []))[0]?.n ?? 0;
  } catch {
    hasAuthSchema = false; // not a Supabase project, or no access to auth
  }

  // soleGrant counts here too: a lone permissive aal gate IS an MFA gate, so
  // reporting "nothing here uses MFA" would be a skip dressed up as a fact.
  const anyGate = gates.permissive.length + gates.restrictive.length + (gates.soleGrant?.length ?? 0);
  if (!hasAuthSchema && anyGate === 0) {
    return OK({
      skipped: true,
      reason: 'no auth.mfa_factors table and no policy references the assurance level — nothing here uses MFA',
      summary: 'skipped — no MFA in use',
    });
  }

  const violations = [];
  for (const row of gates.permissive) {
    const id = `${row.schema}.${row.table}`;
    if (allow.has(id) || allow.has(`${id}.${row.policy}`) || allow.has(row.policy)) continue;
    const v = classifyPermissiveGate({ row, role });
    violations.push({ where: v.where, kind: v.kind, message: v.message, fix: v.fix });
  }

  let tenantTables = [];
  try {
    const tt = tenantTablesSql(cfg.schemas, cfg.tenantColumns);
    tenantTables = await q(tt.text, tt.values);
  } catch { /* coverage reporting is best-effort */ }

  const notes = classifyCoverage({ verifiedFactors, gates, tenantTables, allow });

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned: gates.permissive.length + gates.restrictive.length + (gates.soleGrant?.length ?? 0),
    summary:
      violations.length > 0
        ? `${violations.length} MFA gate(s) are PERMISSIVE and enforce nothing`
        : // A sole-grant permissive gate restricts, so it is a gate that was
          // checked and passed — saying "no MFA gate found" there reads as a
          // skip when it is actually a pass.
          gates.restrictive.length + (gates.soleGrant?.length ?? 0) > 0
          ? `${gates.restrictive.length + (gates.soleGrant?.length ?? 0)} enforcing MFA gate(s) checked`
          : `no MFA gate found` + (notes.length ? `; ${notes.length} note(s)` : ''),
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
