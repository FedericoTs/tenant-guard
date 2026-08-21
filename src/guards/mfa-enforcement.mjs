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

/** Every policy with the one column that decides whether it can restrict. */
export function policiesSql(schemas) {
  return {
    text: `
      select schemaname as schema,
             tablename  as table,
             policyname as policy,
             permissive as permissive,
             cmd        as cmd,
             qual       as qual,
             with_check as with_check
      from pg_catalog.pg_policies
      where schemaname = any($1)
    `,
    values: [schemas],
  };
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
 * a dozen ways — `auth.jwt()->>'aal'`, `request.jwt.claims`, a helper — and all
 * of them mention it.
 */
export function referencesAal(expr) {
  return /\baal\b|'aal'|"aal"|\baal[12]\b/i.test(String(expr ?? ''));
}

/** `pg_policies.permissive` is the text PERMISSIVE / RESTRICTIVE. */
export function isPermissive(row) {
  return String(row?.permissive ?? 'PERMISSIVE').toUpperCase() !== 'RESTRICTIVE';
}

/** The policies that mention the assurance level, split by whether they can enforce it. */
export function classifyAalPolicies(rows) {
  const gates = (rows ?? []).filter((r) => referencesAal(r.qual) || referencesAal(r.with_check));
  return {
    permissive: gates.filter(isPermissive),
    restrictive: gates.filter((r) => !isPermissive(r)),
  };
}

/**
 * The verdict for one permissive gate. Conclusive: this is Postgres semantics,
 * not a judgement about the application.
 */
export function classifyPermissiveGate({ row, role = 'authenticated' }) {
  const id = `${row.schema}.${row.table}`;
  return {
    status: 'leak',
    kind: 'permissive-mfa-gate',
    where: `${id} (policy "${row.policy}")`,
    message:
      `policy "${row.policy}" on ${id} checks the MFA assurance level but is PERMISSIVE, so it enforces nothing. ` +
      `Postgres ORs permissive policies together — this one can only ADD access alongside your other policies, never remove it. ` +
      `A session that never passed the second factor reads exactly what it would have read without this policy. ` +
      `Verified against a real database: with a permissive gate an aal1 session sees every row; with AS RESTRICTIVE it sees none.`,
    fix:
      `A gate has to be restrictive, because only restrictive policies are ANDed:\n` +
      `        DROP POLICY "${row.policy}" ON ${id};\n` +
      `        CREATE POLICY "${row.policy}" ON ${id}\n` +
      `          AS RESTRICTIVE FOR ALL TO ${role}\n` +
      `          USING ((SELECT auth.jwt()->>'aal') = 'aal2');\n` +
      `      If this policy was meant to GRANT access to MFA'd users rather than gate everyone, ` +
      `add "${id}.${row.policy}" to mfaEnforcement.allowlist[] with that reason.`,
  };
}

/** The verdict for the project as a whole. */
export function classifyCoverage({ verifiedFactors = 0, gates, tenantTables = [], allow = new Set() }) {
  const notes = [];

  if (gates.restrictive.length === 0 && gates.permissive.length === 0) {
    if (verifiedFactors > 0) {
      notes.push({
        where: '(project)',
        message:
          `${verifiedFactors} verified MFA factor(s) are enrolled, but no policy in the scanned schemas checks the assurance level. ` +
          `PostgREST honours whatever token the client presents, so a session that never completed the second factor has the same data access as one that did — ` +
          `MFA is gating your login screen, not your data. If that is deliberate (MFA for the admin console only, say), this is fine; if not, add an ` +
          `AS RESTRICTIVE policy requiring aal2 to the tables that matter.`,
      });
    }
    return notes;
  }

  // Some enforcement exists — so which tenant tables are left out of it?
  const covered = new Set(gates.restrictive.map((r) => `${r.schema}.${r.table}`));
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
  const gates = classifyAalPolicies(policies);

  let verifiedFactors = 0;
  let hasAuthSchema = true;
  try {
    verifiedFactors = (await q(verifiedFactorsSql().text, []))[0]?.n ?? 0;
  } catch {
    hasAuthSchema = false; // not a Supabase project, or no access to auth
  }

  if (!hasAuthSchema && gates.permissive.length === 0 && gates.restrictive.length === 0) {
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
    scanned: gates.permissive.length + gates.restrictive.length,
    summary:
      violations.length > 0
        ? `${violations.length} MFA gate(s) are PERMISSIVE and enforce nothing`
        : gates.restrictive.length > 0
          ? `${gates.restrictive.length} restrictive MFA gate(s) checked`
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
