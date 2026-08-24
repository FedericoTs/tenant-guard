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
             t.tgtype      as tgtype,
             fn.nspname    as function_schema,
             p.proname     as function,
             p.prosecdef   as security_definer,
             p.prosrc      as body
      from pg_catalog.pg_trigger t
      join pg_catalog.pg_class c on c.oid = t.tgrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_proc p on p.oid = t.tgfoid
      join pg_catalog.pg_namespace fn on fn.oid = p.pronamespace
      where not t.tgisinternal
        and n.nspname = any($1)
      order by n.nspname, c.relname, t.tgname
    `,
    values: [schemas],
  };
}

/**
 * Can this trigger cancel the row by returning NULL?
 *
 * Only a ROW trigger that fires BEFORE, or an INSTEAD OF row trigger on a view.
 * Everywhere else the return value is discarded, so `RETURN NULL` is a no-op and
 * counting it as enforcement reports a trigger that decides nothing.
 *
 * Measured in pglite by reading pg_trigger.tgtype directly:
 *   BEFORE ... FOR EACH ROW        = 7   (0b0000111)  bit1 ROW, bit2 BEFORE
 *   AFTER ... FOR EACH ROW         = 5   (0b0000101)  bit1 ROW
 *   AFTER ... FOR EACH STATEMENT   = 4   (0b0000100)
 *   BEFORE ... FOR EACH STATEMENT  = 6   (0b0000110)
 *   INSTEAD OF ... FOR EACH ROW    = 69  (0b1000101)  bit1 ROW, bit64 INSTEAD
 * Confirmed separately that `RETURN NULL` from an AFTER row trigger cancels
 * nothing: the INSERT it "rejected" was still in the table afterwards.
 *
 * Unknown tgtype (undefined/null — a caller passing a hand-built trigger, or an
 * older row shape) returns true. Erring toward "it can cancel" keeps this from
 * silently dropping real findings; the visibility measurement still has to agree
 * before anything is reported.
 */
export function cancelsRowOnNull(tgtype) {
  if (tgtype === undefined || tgtype === null) return true;
  const n = Number(tgtype);
  if (!Number.isFinite(n)) return true;
  return (n & 1) !== 0 && ((n & 2) !== 0 || (n & 64) !== 0);
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
 * `RAISE` aborts the statement wherever it fires. `RETURN NULL` only cancels the
 * row where the return value is honoured, which is why `tgtype` is a parameter:
 * see cancelsRowOnNull. Both mean the function's decision is load-bearing. A
 * trigger that only stamps a column reads the same tables and is not a finding —
 * requiring this signal is what keeps the guard off every `set_updated_at`.
 *
 * `tgtype` is optional so the exported helper stays usable without a pg_trigger
 * row; omitted, `RETURN NULL` counts, as it did before.
 */
export function enforcesSomething(body, tgtype) {
  const s = String(body ?? '');
  if (/\braise\s+(exception|error)\b/i.test(s)) return true; // aborts wherever it fires
  // `RETURN NULL` only enforces where the return value is honoured. An
  // append-only audit trigger (AFTER INSERT, writes a row, RETURN NULL) used to
  // land here and get reported as enforcing a rule it does not enforce.
  return /\breturn\s+null\b/i.test(s) && cancelsRowOnNull(tgtype);
}

/**
 * Split a plpgsql body into executable code and the string literals that are
 * arguments to EXECUTE.
 *
 * Written here rather than reusing `stripSqlComments` because that helper runs
 * before quoting is known, so a `--` inside a message literal
 * (`raise exception 'a--b'`) eats the closing quote and desynchronises
 * everything after it. One pass that tracks quoting AND comments together is the
 * only version that survives real trigger bodies.
 *
 * Dollar-quoting is recognised (`$$`, `$tag$`) but `$1` placeholders are not,
 * since the tag must be an identifier or empty. Block comments nest, as in
 * Postgres.
 */
export function splitBody(body) {
  const s = String(body ?? '');
  let code = '';
  const dynamic = [];
  let stmtStart = 0; // offset in `code` where the current statement began
  let pending = []; // literals seen in the statement being scanned
  let i = 0;
  // Literals of ONE statement are joined back together, because that is what
  // `||` does at runtime: `execute 'select 1 from ' || quote_ident('profiles')`
  // is a read of profiles, and scanning the fragments separately misses it.
  // Statements stay apart so two unrelated strings cannot form a phantom read.
  const endStatement = () => {
    if (pending.length && /\bexecute\b/i.test(code.slice(stmtStart))) dynamic.push(pending.join(' '));
    pending = [];
    stmtStart = code.length;
  };
  while (i < s.length) {
    const ch = s[i];
    if (ch === '-' && s[i + 1] === '-') {
      const nl = s.indexOf('\n', i);
      i = nl === -1 ? s.length : nl;
      code += ' ';
      continue;
    }
    if (ch === '/' && s[i + 1] === '*') {
      let depth = 1;
      i += 2;
      while (i < s.length && depth > 0) {
        if (s[i] === '/' && s[i + 1] === '*') { depth++; i += 2; continue; }
        if (s[i] === '*' && s[i + 1] === '/') { depth--; i += 2; continue; }
        i++;
      }
      code += ' ';
      continue;
    }
    if (ch === '"') {
      // A quoted identifier is code, not text — and consuming it here is also
      // what stops a `--` or a `'` inside one from desynchronising the scan.
      let j = i + 1;
      let ident = '"';
      while (j < s.length) {
        if (s[j] === '"' && s[j + 1] === '"') { ident += '""'; j += 2; continue; }
        if (s[j] === '"') break;
        ident += s[j];
        j++;
      }
      code += `${ident}"`;
      i = j + 1;
      continue;
    }
    if (ch === "'") {
      let j = i + 1;
      let lit = '';
      while (j < s.length) {
        if (s[j] === "'" && s[j + 1] === "'") { lit += "'"; j += 2; continue; }
        if (s[j] === "'") break;
        lit += s[j];
        j++;
      }
      // Held until the statement ends: it only counts as SQL if this statement
      // turns out to be an EXECUTE, which the keyword may not have revealed yet.
      pending.push(lit);
      code += ' ';
      i = j + 1;
      continue;
    }
    const dq = ch === '$' ? /^\$([A-Za-z_]\w*)?\$/.exec(s.slice(i)) : null;
    if (dq) {
      const tag = dq[0];
      const end = s.indexOf(tag, i + tag.length);
      const lit = end === -1 ? s.slice(i + tag.length) : s.slice(i + tag.length, end);
      pending.push(lit);
      code += ' ';
      i = end === -1 ? s.length : end + tag.length;
      continue;
    }
    code += ch;
    i++;
    if (ch === ';') endStatement();
  }
  endStatement();
  return { code, dynamic };
}

/**
 * Which of the RLS-protected tables this body actually READS.
 *
 * Matching the bare name anywhere in `prosrc` reported the textbook append-only
 * audit trigger — `raise exception 'audit_log is append-only'` reads nothing at
 * all, and the guard said it was "enforcing a rule by reading public.audit_log
 * (0 of 4 rows visible)". Changing only the message text silenced it. Same
 * failure from a `--` comment naming the table.
 *
 * So: comments and string literals are removed first, and what is left must sit
 * in a position where RLS narrows what the statement sees —
 *   FROM / JOIN / USING            a read
 *   UPDATE [ONLY] t / DELETE FROM  the row match is RLS-filtered, so also a read
 *   MERGE INTO t                   the ON clause matches against visible rows
 * `INSERT INTO t` is deliberately absent: a VALUES insert consults no row of the
 * target, and counting the write target as a read is what put an append-only
 * audit trigger on the failure list. A read of that same table elsewhere in the
 * body (`insert into t select … from t`) still matches on the FROM.
 *
 * `(?!\s*=)` drops `RAISE … USING message = '…'`, where the option keyword after
 * USING would otherwise look like a relation.
 */
export function tablesRead(body, rlsTables = []) {
  const { code, dynamic } = splitBody(body);
  const haystack = [code, ...dynamic].join('\n;\n');
  return rlsTables.filter((t) => {
    const bare = t.split('.').pop().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(
      `\\b(?:from|join|using|merge\\s+into|update(?:\\s+only)?)\\s+` +
        `(?:"?[A-Za-z_]\\w*"?\\s*\\.\\s*)?"?${bare}"?\\b(?!\\s*=)`,
      'i',
    );
    return re.test(haystack);
  });
}

/** The verdict for one trigger, given the tables it reads and cannot fully see. */
export function classifyTrigger({ trigger, hidden, role }) {
  const id = `${trigger.schema}.${trigger.table}`;
  // The function does NOT have to live in the table's schema, and the ALTER
  // statements below used to assume it did. Measured: with the function in
  // `private` and the trigger on `public.profiles`, the emitted
  // `ALTER FUNCTION public.check_unique_username() SECURITY DEFINER` errored —
  // and when an unrelated same-named function existed in `public`, it RAN, left
  // the real function untouched, and promoted the bystander to SECURITY DEFINER.
  // Fallback to the table schema keeps hand-built trigger objects (tests,
  // external callers) from rendering `undefined.f()`.
  const fnSchema = trigger.function_schema ?? trigger.schema;
  const fn = `${fnSchema}.${trigger.function}`;
  // The body resolves unqualified names against the TABLE's schema, and may call
  // helpers unqualified in its OWN schema. Name both; pg_temp stays last.
  const searchPath = [...new Set(['pg_catalog', trigger.schema, fnSchema])].join(', ');
  return {
    where: `${id} (trigger "${trigger.trigger}")`,
    kind: 'trigger-reads-hidden-rows',
    message:
      `trigger "${trigger.trigger}" on ${id} enforces a rule by reading ${hidden.map((h) => `${h.table} (${h.visible} of ${h.total} rows visible)`).join(', ')}, ` +
      `and its function "${fn}" is NOT SECURITY DEFINER — so it runs as whoever is writing and sees only what RLS shows them. ` +
      `The check is being evaluated against a partial view of the table, which means it passes on rows it was written to reject. ` +
      `Verified end to end on this exact shape: a uniqueness trigger in invoker mode let the duplicate INSERT through, and the identical trigger marked SECURITY DEFINER raised the exception. ` +
      `Nothing errors and nothing logs — hardening the table is what breaks the guarantee, so the better your RLS gets, the more completely this stops working.`,
    fix:
      `Prefer a constraint. It does not depend on who is writing, so it cannot be defeated the way the trigger just was:\n` +
      `        CREATE UNIQUE INDEX ON ${id} (<column>);\n` +
      `      Scope it by the tenant column where the value is only unique per tenant — and note that a unique constraint on a tenant table is itself readable as an existence oracle, which the constraint-oracles guard covers.\n` +
      `      If it has to stay a trigger, SECURITY DEFINER is the mechanism, but it is NOT unconditional:\n` +
      `        ALTER FUNCTION ${fn}() SECURITY DEFINER;\n` +
      `        ALTER FUNCTION ${fn}() SET search_path = ${searchPath}, pg_temp;\n` +
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
    if (!enforcesSomething(t.body, t.tgtype)) continue; // records rather than enforces
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
  // Each count in its own savepoint. A table the role cannot read raises 42501,
  // and without a savepoint that aborts the transaction — every later count then
  // fails too and is recorded as "sees nothing", which reads as a finding. The
  // service-role-only table that triggers it is in most Supabase projects.
  const counted = async (sql) => {
    await query('savepoint tg_c', []);
    try {
      const n = (await q(sql, []))[0].n;
      await query('release savepoint tg_c', []);
      return { ok: true, n };
    } catch {
      try { await query('rollback to savepoint tg_c', []); await query('release savepoint tg_c', []); }
      catch { /* outer rollback still discards */ }
      return { ok: false };
    }
  };
  try {
    for (const id of new Set(candidates.flatMap((c) => c.reads))) {
      const [schema, table] = id.split('.');
      const r = await counted(`select count(*)::int as n from "${schema}"."${table}"`);
      if (r.ok) totals.set(id, r.n); // otherwise the table is simply not compared
    }
    await query(`set local role ${role}`, []);
    for (const id of totals.keys()) {
      const [schema, table] = id.split('.');
      const r = await counted(`select count(*)::int as n from "${schema}"."${table}"`);
      // A denial means it sees nothing, which IS the fact we are measuring; a
      // savepoint is what keeps that from also poisoning every later count.
      visible.set(id, r.ok ? r.n : 0);
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
      // An EMPTY table makes the comparison vacuous: 0 < 0 is false, so it fell
      // into the reassurance branch and asserted "sees every row, nothing is
      // being missed" — on a table where nothing was compared. Say which it is.
      const empty = c.reads.every((id) => (totals.get(id) ?? 0) === 0);
      notes.push({
        where: `${c.schema}.${c.table} (trigger "${c.trigger}")`,
        message: empty
          ? `trigger "${c.trigger}" enforces a rule by reading ${c.reads.join(', ')}, which has RLS on, and its function is not SECURITY DEFINER — so it evaluates against whatever the writing role can see. That table is EMPTY, so nothing could be compared and this is NOT proven either way. Seed it, or re-run against a database with data.`
          : `trigger "${c.trigger}" enforces a rule by reading ${c.reads.join(', ')}, which has RLS on, and its function is not SECURITY DEFINER — so it evaluates against whatever the writing role can see. ` +
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
