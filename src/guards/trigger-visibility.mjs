/**
 * Guard: a trigger that ENFORCES something by reading an RLS-protected table.
 *
 * A trigger function runs as the invoker unless it is declared SECURITY DEFINER.
 * So a `BEFORE INSERT` trigger that checks uniqueness with
 * `IF EXISTS (SELECT 1 FROM profiles WHERE username = NEW.username)` sees only
 * the rows RLS lets the *writing* role see. The day someone locks that table
 * down — which is the correct thing to do — the check stops finding collisions
 * and silently starts passing.
 *
 * Reproduced end to end, and it is worse than a missed check: the duplicate is
 * INSERTED. With the trigger in invoker mode the guard saw nothing and the row
 * went in; the identical trigger marked SECURITY DEFINER raised the exception.
 * Nothing errors, nothing logs, and the constraint you believe you have is gone.
 *
 * SECURITY DEFINER is the mechanism but NOT an unconditional fix, and the fix
 * text says so: it does not bypass RLS, it changes which role RLS is evaluated
 * for. It only helps when that role is exempt from the policies on the table —
 * the owner without FORCE ROW LEVEL SECURITY, a superuser, or BYPASSRLS. Also
 * verified: the same definer trigger owned by a role that merely holds GRANTs on
 * the table still let the duplicate through. A unique constraint has no such
 * precondition, which is why it is recommended first.
 *
 * This is the silent-failure shape the whole tool is aimed at, in its purest
 * form: hardening the database is what breaks the guarantee, so the safer your
 * RLS gets, the more thoroughly the trigger stops working.
 *
 * `shadow-tables` covers trigger COPIES — a trigger writing tenant data
 * somewhere unprotected. This is about trigger READS, which change meaning
 * depending on who writes.
 *
 * Conclusive only when all of it lines up: the function is not SECURITY DEFINER,
 * it reads a table with RLS enabled, it ENFORCES (raises, or returns NULL to
 * cancel the row), and the app role demonstrably sees fewer rows of that table
 * than exist. A trigger that merely stamps `user_id` reads the same table and is
 * not a finding, which is why the enforcement signal is required.
 */
import { safeRole, DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'trigger-visibility',
  title: 'Triggers that enforce a rule by reading a table RLS hides from them',
  why: "A trigger function runs as the INVOKER unless declared SECURITY DEFINER, so a uniqueness or existence check inside one sees only the rows RLS shows the writing role. Locking the table down — the correct thing to do — makes the check stop finding collisions and silently start passing. Verified: the duplicate row was inserted with the trigger in invoker mode and rejected once the function ran as a role exempt from the table policies. SECURITY DEFINER alone is not sufficient — it changes which role RLS is evaluated for, not whether RLS applies.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  schemas: ['public'],
  allowlist: [], // "trigger_name" or "schema.table.trigger_name"
};

// ── pure helpers ─────────────────────────────────────────────────────

/**
 * Every non-internal trigger with its function's body and security mode.
 * `tgisinternal` excludes the ones Postgres creates for constraints, which have
 * no user-written body to read.
 */
export function triggersSql(schemas) {
  return {
    text: `
      select n.nspname     as schema,
             c.relname     as table,
             t.tgname      as trigger,
             p.proname     as function,
             p.prosecdef   as security_definer,
             p.prosrc      as body
      from pg_catalog.pg_trigger t
      join pg_catalog.pg_class c on c.oid = t.tgrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_proc p on p.oid = t.tgfoid
      where not t.tgisinternal
        and n.nspname = any($1)
      order by n.nspname, c.relname, t.tgname
    `,
    values: [schemas],
  };
}

/** Tables with RLS on — the ones whose rows a trigger may not fully see. */
export function rlsTablesSql(schemas) {
  return {
    text: `
      select n.nspname as schema, c.relname as table
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      where c.relkind in ('r', 'p') and c.relrowsecurity and n.nspname = any($1)
      order by 1, 2
    `,
    values: [schemas],
  };
}

/**
 * Does this body ENFORCE anything, or does it just record?
 *
 * `RAISE` aborts the statement; `RETURN NULL` from a BEFORE trigger cancels the
 * row. Both mean the function's decision is load-bearing. A trigger that only
 * stamps a column reads the same tables and is not a finding — requiring this
 * signal is what keeps the guard off every `set_updated_at` in the schema.
 */
export function enforcesSomething(body) {
  const s = String(body ?? '');
  return /\braise\s+(exception|error)\b/i.test(s) || /\breturn\s+null\b/i.test(s);
}

/** Which of the RLS-protected tables this body reads by name. */
export function tablesRead(body, rlsTables = []) {
  const s = String(body ?? '');
  return rlsTables.filter((t) => {
    const bare = t.split('.').pop().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\b${bare}\\b`, 'i').test(s);
  });
}

/** The verdict for one trigger, given the tables it reads and cannot fully see. */
export function classifyTrigger({ trigger, hidden, role }) {
  const id = `${trigger.schema}.${trigger.table}`;
  return {
    where: `${id} (trigger "${trigger.trigger}")`,
    kind: 'trigger-reads-hidden-rows',
    message:
      `trigger "${trigger.trigger}" on ${id} enforces a rule by reading ${hidden.map((h) => `${h.table} (${h.visible} of ${h.total} rows visible)`).join(', ')}, ` +
      `and its function "${trigger.function}" is NOT SECURITY DEFINER — so it runs as whoever is writing and sees only what RLS shows them. ` +
      `The check is being evaluated against a partial view of the table, which means it passes on rows it was written to reject. ` +
      `Verified end to end on this exact shape: a uniqueness trigger in invoker mode let the duplicate INSERT through, and the identical trigger marked SECURITY DEFINER raised the exception. ` +
      `Nothing errors and nothing logs — hardening the table is what breaks the guarantee, so the better your RLS gets, the more completely this stops working.`,
    fix:
      `Prefer a constraint. It does not depend on who is writing, so it cannot be defeated the way the trigger just was:\n` +
      `        CREATE UNIQUE INDEX ON ${id} (<column>);\n` +
      `      Scope it by the tenant column where the value is only unique per tenant — and note that a unique constraint on a tenant table is itself readable as an existence oracle, which the constraint-oracles guard covers.\n` +
      `      If it has to stay a trigger, SECURITY DEFINER is the mechanism, but it is NOT unconditional:\n` +
      `        ALTER FUNCTION ${trigger.schema}.${trigger.function}() SECURITY DEFINER;\n` +
      `        ALTER FUNCTION ${trigger.schema}.${trigger.function}() SET search_path = pg_catalog, ${trigger.schema}, pg_temp;\n` +
      `      SECURITY DEFINER does not bypass RLS — it changes which role RLS is evaluated for. It only fixes this if that role is EXEMPT from the policies on ${id}: the table owner without FORCE ROW LEVEL SECURITY, a superuser, or a BYPASSRLS role. Verified: the same definer trigger owned by a role that merely holds GRANTs on the table still let the duplicate through, so check who owns the function.\n` +
      `      Pin the search_path in the same breath and name pg_temp — a SECURITY DEFINER function without a complete pin is the hijack \`definer-rpc\` reports.\n` +
      `      If this trigger is MEANT to see only the writer's own rows, add "${trigger.trigger}" to triggerVisibility.allowlist[] with that reason.`,
  };
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const role = safeRole(cfg.role);
  const allow = new Set(cfg.allowlist);
  const q = async (text, values) => (await query(text, values)).rows;

  const tq = triggersSql(cfg.schemas);
  const triggers = await q(tq.text, tq.values);
  if (!triggers.length) return OK({ skipped: true, reason: 'no user triggers in the scanned schemas', summary: 'skipped — no triggers' });

  const rq = rlsTablesSql(cfg.schemas);
  const rlsTables = (await q(rq.text, rq.values)).map((r) => `${r.schema}.${r.table}`);
  if (!rlsTables.length) return OK({ skipped: true, reason: 'no RLS-protected tables — a trigger read cannot be narrowed', summary: 'skipped — no RLS tables' });

  // Which candidates are worth measuring: enforcing, invoker-mode, reading a
  // protected table. Everything else is silent.
  const candidates = [];
  for (const t of triggers) {
    if (t.security_definer === true || t.security_definer === 't') continue; // runs as owner already
    if (allow.has(t.trigger) || allow.has(`${t.schema}.${t.table}.${t.trigger}`)) continue;
    if (!enforcesSomething(t.body)) continue; // records rather than enforces
    const reads = tablesRead(t.body, rlsTables);
    if (reads.length) candidates.push({ ...t, reads });
  }
  if (!candidates.length) {
    return OK({ scanned: triggers.length, summary: `${triggers.length} trigger(s) checked; none enforce a rule over rows RLS hides` });
  }

  // The measurement that makes it conclusive: does the app role actually see
  // fewer rows than exist? Counted first as the connection role (unrestricted),
  // then as the app role, inside one rolled-back transaction.
  const totals = new Map();
  const visible = new Map();
  await query('begin', []);
  try {
    for (const id of new Set(candidates.flatMap((c) => c.reads))) {
      const [schema, table] = id.split('.');
      const sql = `select count(*)::int as n from "${schema}"."${table}"`;
      try { totals.set(id, (await q(sql, []))[0].n); } catch { /* skip this table */ }
    }
    await query(`set local role ${role}`, []);
    for (const id of totals.keys()) {
      const [schema, table] = id.split('.');
      try { visible.set(id, (await q(`select count(*)::int as n from "${schema}"."${table}"`, []))[0].n); }
      catch { visible.set(id, 0); } // permission denied — it sees nothing at all
    }
  } finally {
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  const violations = [];
  const notes = [];
  for (const c of candidates) {
    const hidden = c.reads
      .filter((id) => totals.has(id) && visible.has(id) && visible.get(id) < totals.get(id))
      .map((id) => ({ table: id, visible: visible.get(id), total: totals.get(id) }));

    if (hidden.length) violations.push(classifyTrigger({ trigger: c, hidden, role }));
    else {
      notes.push({
        where: `${c.schema}.${c.table} (trigger "${c.trigger}")`,
        message:
          `trigger "${c.trigger}" enforces a rule by reading ${c.reads.join(', ')}, which has RLS on, and its function is not SECURITY DEFINER — so it evaluates against whatever the writing role can see. ` +
          `Right now "${role}" sees every row, so nothing is being missed; the day a policy narrows that table this check starts passing silently. Not a finding, and worth knowing before it becomes one.`,
      });
    }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned: triggers.length,
    summary:
      violations.length > 0
        ? `${violations.length} trigger(s) enforce a rule over rows they cannot see`
        : `${triggers.length} trigger(s) checked` + (notes.length ? `; ${notes.length} note(s)` : ''),
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
