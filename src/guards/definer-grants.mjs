/**
 * Guard: anon-callable mutating SECURITY DEFINER functions.
 *
 * Postgres grants EXECUTE to PUBLIC by default on every new function, and in a
 * Supabase project the `anon` role inherits through PUBLIC. So a new
 * SECURITY DEFINER function that MUTATES a tenant table becomes callable by an
 * unauthenticated client over PostgREST (`/rest/v1/rpc/<name>`) unless EXECUTE
 * is revoked from PUBLIC. Revoking from `anon` alone is a NO-OP — the grant
 * lives on PUBLIC. This is the class of bug a general SAST scanner misses
 * because it requires knowing how Postgres default grants + PostgREST exposure
 * interact.
 *
 * The convention this enforces: any NEW migration (number > baseline) that
 * creates a SECURITY DEFINER function which (a) is not a trigger function and
 * (b) mutates, MUST revoke EXECUTE from PUBLIC in the same migration — unless
 * the function is on an explicit allowlist of intentionally pre-auth functions.
 *
 * Pure helpers are I/O-free and unit-tested. Zero dependencies.
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Order migrations the way the tools that apply them do: by FULL FILENAME,
 * lexicographically.
 *
 * This used to sort on the numeric prefix alone. For two files sharing a prefix
 * — `20260531_a_create.sql` and `20260531_b_drop.sql`, which is the ordinary
 * Supabase date convention — the comparator returned 0, so a stable sort kept
 * `readdirSync` order, i.e. **filesystem order**. Net-state-of-history reasoning
 * (a REVOKE here, a re-GRANT there; which CREATE VIEW is the final one) was
 * therefore machine-dependent on exactly the input shape it flags, and could be
 * evaluated in the opposite order from the one Postgres will see.
 */
export function compareMigrations(a, b) {
  return String(a?.name ?? a).localeCompare(String(b?.name ?? b), 'en');
}

/**
 * Does lexicographic order disagree with numeric order? That happens with
 * UNPADDED numbering (`9_x.sql` sorts after `10_y.sql`), where the filenames say
 * one thing and the numbering another — worth saying out loud, because both this
 * tool and the migration runner follow the filenames.
 */
export function lexicographicDisagreesWithNumeric(filenames) {
  const sql = [...(filenames ?? [])].filter((f) => f.endsWith('.sql'));
  const byName = [...sql].sort((a, b) => a.localeCompare(b, 'en'));
  const byNumber = [...sql].sort((a, b) => {
    const d = (migrationNumber(a) ?? 0) - (migrationNumber(b) ?? 0);
    return d !== 0 ? d : a.localeCompare(b, 'en');
  });
  return byName.some((f, i) => f !== byNumber[i]);
}

/** Leading numeric prefix of a migration filename, or null. */
export function migrationNumber(filename) {
  const m = filename.match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

/** Strip SQL comments, so prose about deleting things isn't read as DML. */
export function stripSqlComments(sql) {
  return String(sql ?? '')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n]*/g, ' ');
}

/**
 * The function's own body, from its `AS` clause — not the rest of the file.
 *
 * Reading the whole segment up to the next `CREATE FUNCTION` swept in every
 * statement that followed, so a neighbouring `CREATE POLICY … FOR INSERT` made a
 * pure `SELECT` predicate look like DML. That mislabelling produced a REVOKE
 * recommendation which, applied, took a production app down.
 *
 * Handles dollar-quoting with or without a tag, single-quoted bodies, and the
 * SQL-standard `BEGIN ATOMIC … END`. Returns null when none is recognisable,
 * which the caller must treat as "unknown", never as "safe".
 */
export function extractFunctionBody(segment) {
  const s = String(segment ?? '');

  const dollar = /\bas\s+\$([A-Za-z_][A-Za-z0-9_]*|)\$/i.exec(s);
  if (dollar) {
    const tag = `$${dollar[1]}$`;
    const from = dollar.index + dollar[0].length;
    const to = s.indexOf(tag, from);
    if (to !== -1) return s.slice(from, to);
  }

  const atomic = /\bbegin\s+atomic\b/i.exec(s);
  if (atomic) {
    const from = atomic.index + atomic[0].length;
    const to = s.toLowerCase().lastIndexOf('end');
    if (to > from) return s.slice(from, to);
  }

  const quoted = /\bas\s+'((?:[^']|'')*)'/i.exec(s);
  if (quoted) return quoted[1].replace(/''/g, "'");

  return null;
}

/**
 * Does this body actually write? Judged on statements, not bare words: `for
 * update` is a lock, `updated_at` is a column, and a comment is not code.
 */
export function bodyMutates(body) {
  const sql = stripSqlComments(body).toLowerCase().replace(/\bfor\s+(no\s+key\s+)?update\b/g, ' ');
  return /\b(insert\s+into|delete\s+from|update\s+[a-z_"]|merge\s+into|truncate\s|copy\s|create\s|drop\s|alter\s|grant\s|revoke\s)/.test(sql);
}

/**
 * Parse a migration's SQL into EVERY function it defines, with the properties
 * that decide safety. Heuristic (no full SQL parser), but scoped to the function
 * itself rather than to whatever follows it in the file.
 *
 * `mutates` is decided by VOLATILITY first, because Postgres enforces it: a
 * `STABLE` or `IMMUTABLE` function cannot write, and the server rejects it if it
 * tries. That is a guarantee, not a heuristic, and it is what makes an RLS
 * predicate provably safe. Only when volatility is unstated does the body get
 * read; only when the body cannot be found is it treated as unknown.
 *
 * Returns [{ name, isDefiner, returnsTrigger, mutates, volatility, bodyKnown }].
 */
export function extractFunctionDefs(sql) {
  const out = [];
  const re = /create\s+(?:or\s+replace\s+)?function\s+([a-z0-9_."]+)\s*\(/gi;
  const starts = [];
  let m;
  while ((m = re.exec(sql)) !== null) starts.push({ index: m.index, name: m[1] });

  for (let i = 0; i < starts.length; i++) {
    const start = starts[i].index;
    const end = i + 1 < starts.length ? starts[i + 1].index : sql.length;
    const segment = sql.slice(start, end);
    const header = stripSqlComments(segment).toLowerCase();
    const rawName = starts[i].name.replace(/"/g, '');
    const name = rawName.includes('.') ? rawName.split('.').pop() : rawName;

    const volatility = /\bimmutable\b/.test(header) ? 'immutable'
      : /\bstable\b/.test(header) ? 'stable'
        : /\bvolatile\b/.test(header) ? 'volatile' : null;

    const body = extractFunctionBody(segment);
    // Postgres will not let a non-volatile function write, so this is settled.
    const mutates = volatility === 'stable' || volatility === 'immutable'
      ? false
      : body !== null
        ? bodyMutates(body)
        : /\b(insert\s+into|delete\s+from|update\s+[a-z_"])/.test(header);

    out.push({
      name,
      isDefiner: /security\s+definer/.test(header),
      returnsTrigger: /returns\s+trigger/.test(header),
      mutates,
      volatility,
      bodyKnown: body !== null,
    });
  }
  return out;
}

/**
 * Function names referenced from inside a `CREATE POLICY` expression.
 *
 * Postgres requires the CALLING role to hold EXECUTE on a function used in a
 * policy — even a `SECURITY DEFINER` one. So revoking EXECUTE from PUBLIC on an
 * RLS helper does not harden anything; it denies every role the ability to
 * evaluate its own row policy. Reproduced: after such a revoke, `anon` SELECT on
 * the protected table fails with 42501. These functions must never be told to
 * revoke.
 */
export function policyReferencedFunctions(sql) {
  const names = new Set();
  const text = stripSqlComments(sql);
  const re = /create\s+policy\b[\s\S]*?(?:;|$)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    for (const call of m[0].matchAll(/([a-z_][a-z0-9_]*)\s*\(/gi)) {
      names.add(call[1].toLowerCase());
    }
  }
  // Words that are syntax, not helpers.
  for (const kw of ['policy', 'check', 'using', 'select', 'exists', 'in', 'values', 'and', 'or', 'not', 'any', 'all', 'coalesce', 'cast']) {
    names.delete(kw);
  }
  return names;
}

/** The SECURITY DEFINER functions in `sql` (a filtered view of extractFunctionDefs). */
export function extractDefinerFunctions(sql) {
  return extractFunctionDefs(sql)
    .filter((f) => f.isDefiner)
    .map(({ isDefiner, ...f }) => f); // eslint-disable-line no-unused-vars
}

/** Does `sql` revoke EXECUTE on function `name` from PUBLIC or anon? */
export function revokesAnonExecute(sql, name) {
  const lower = sql.toLowerCase();
  const n = name.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(
    `revoke[\\s\\S]{0,240}?\\bon\\s+function[\\s\\S]{0,240}?\\b${n}\\b[\\s\\S]{0,240}?\\bfrom\\b[\\s\\S]{0,160}?\\b(public|anon)\\b`,
  );
  return re.test(lower);
}

/**
 * Find convention violations across the given migrations, judged on the FINAL
 * state of history — not per file. A function that ships unsafe and is fixed by
 * a REVOKE (or by dropping SECURITY DEFINER) in a *later* repair migration is
 * not a live leak, so it isn't flagged. This mirrors an ArchUnit-style check
 * that only asserts on a function's final definition.
 * @param {{name:string, sql:string}[]} files
 * @param {{ baseline?: number, allowlist?: string[] }} opts
 */
export function findDefinerGrantViolations(files, { baseline = 0, allowlist = [] } = {}) {
  const allow = new Set(allowlist);
  const sorted = [...files].sort(compareMigrations);

  // The latest definition of each function name across all history.
  const latest = new Map(); // name -> { isDefiner, returnsTrigger, mutates, file, num }
  for (const { name: filename, sql } of sorted) {
    const num = migrationNumber(filename);
    for (const fn of extractFunctionDefs(sql)) {
      latest.set(fn.name, { ...fn, file: filename, num });
    }
  }

  // Is EXECUTE ever revoked from PUBLIC/anon for a name, anywhere in history?
  // CREATE OR REPLACE preserves grants, so a revoke that appears at all keeps it
  // revoked — the "fixed later in a repair migration" case.
  const revoked = new Set();
  for (const name of latest.keys()) {
    if (sorted.some(({ sql }) => revokesAnonExecute(sql, name))) revoked.add(name);
  }

  // Functions used inside a policy expression, anywhere in history. Postgres
  // requires the CALLING role to hold EXECUTE on these even when they are
  // SECURITY DEFINER, so revoking from PUBLIC breaks every read the policy
  // guards. They can never carry a revoke recommendation.
  const rlsHelpers = new Set();
  for (const { sql } of sorted) {
    for (const n of policyReferencedFunctions(sql)) rlsHelpers.add(n);
  }

  // Violation only when the FINAL definition is a mutating, non-trigger
  // SECURITY DEFINER function above the baseline, never revoked, not allowlisted.
  const violations = [];
  for (const [name, def] of latest) {
    if (!def.isDefiner || def.returnsTrigger || !def.mutates) continue;
    if ((def.num ?? 0) <= baseline) continue;
    if (allow.has(name)) continue;
    if (revoked.has(name)) continue;
    violations.push({ file: def.file, fn: name, rlsHelper: rlsHelpers.has(name.toLowerCase()) });
  }
  return violations;
}

/**
 * Definer functions used by a policy that this guard deliberately does NOT flag.
 * Surfaced as notes so the category is visible rather than silently skipped.
 */
export function findRlsHelpers(files, { baseline = 0 } = {}) {
  const sorted = [...files].sort(compareMigrations);
  const referenced = new Set();
  for (const { sql } of sorted) for (const n of policyReferencedFunctions(sql)) referenced.add(n);

  const latest = new Map();
  for (const { name: filename, sql } of sorted) {
    const num = migrationNumber(filename);
    for (const fn of extractFunctionDefs(sql)) latest.set(fn.name, { ...fn, file: filename, num });
  }
  const out = [];
  for (const [name, def] of latest) {
    if (!def.isDefiner || def.returnsTrigger) continue;
    if ((def.num ?? 0) <= baseline) continue;
    if (!referenced.has(name.toLowerCase())) continue;
    out.push({ file: def.file, fn: name, volatility: def.volatility, mutates: def.mutates });
  }
  return out;
}

export const meta = {
  id: 'definer-grants',
  title: 'Anon-callable SECURITY DEFINER functions',
  why: 'A new mutating SECURITY DEFINER function is callable by anon over PostgREST unless EXECUTE is revoked from PUBLIC (revoking from anon alone is a no-op).',
};

/**
 * @param {object} config { dir, baseline?: number, allowlist?: string[] }
 */
export function run(config = {}) {
  const dir = config.dir;
  if (!dir || !existsSync(dir)) {
    return {
      id: meta.id,
      ok: true,
      skipped: true,
      reason: dir ? `migrations dir not found: ${dir}` : 'no migrations dir configured',
      violations: [],
      scanned: 0,
      summary: 'skipped',
    };
  }
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .map((f) => ({ name: f, sql: readFileSync(join(dir, f), 'utf8') }));
  const baseline = config.baseline ?? 0;
  const raw = findDefinerGrantViolations(files, { baseline, allowlist: config.allowlist ?? [] });
  const scanned = files.filter((f) => (migrationNumber(f.name) ?? 0) > baseline).length;

  const violations = raw.map((v) => (v.rlsHelper
    ? {
      // Mutating AND used by a policy. Still a real risk, but the usual fix is
      // the wrong one: revoking EXECUTE would deny every role the ability to
      // evaluate its own row policy, so it must not be recommended here.
      where: v.file,
      kind: 'definer-grant-rls-helper',
      message:
        `function "${v.fn}" is SECURITY DEFINER, appears to mutate, AND is referenced by a CREATE POLICY expression. ` +
        `Its EXECUTE grant is load-bearing: Postgres requires the CALLING role to hold EXECUTE even for a definer function used in a policy, so revoking it from PUBLIC would make every read that policy guards fail with 42501.`,
      fix:
        `Do NOT revoke EXECUTE on this one. Either split it — a STABLE predicate for the policy, and a separate VOLATILE function for the writes, with the revoke on that one —\n` +
        `      or confirm the mutation is intended and add "${v.fn}" to definerGrants.allowlist[].`,
    }
    : {
      where: v.file,
      message: `function "${v.fn}" is SECURITY DEFINER + mutates but EXECUTE is not revoked from PUBLIC/anon`,
      fix:
        `In the SAME migration add:  REVOKE EXECUTE ON FUNCTION public.${v.fn}(<args>) FROM PUBLIC, anon;\n` +
        `      If it is intentionally pre-auth, add "${v.fn}" to definerGrants.allowlist[] in your tenant-guard config.`,
    }));

  // The safe, common pattern, named so it reads as recognised rather than missed.
  const notes = findRlsHelpers(files, { baseline })
    .filter((h) => !h.mutates)
    .map((h) => ({
      where: h.file,
      message:
        `"${h.fn}" is a SECURITY DEFINER ${h.volatility ?? 'non-mutating'} predicate referenced by a policy — an RLS helper, which is the correct pattern. ` +
        `Not flagged, and its EXECUTE grant must stay: revoking it would break every read the policy guards.`,
    }));

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length === 0
        ? `${scanned} migration(s) above baseline ${baseline} scanned; ${files.length} total`
        : `${violations.length} unsafe function(s)`,
  };
}
