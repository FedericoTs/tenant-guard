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
    // The schema the CREATE actually named, and the exact spelling to put in an
    // ALTER/REVOKE. Everything downstream matches on the BARE name (allowlists,
    // policy references, the revoke scan), so `name` stays bare — but the advice
    // has to name the real function. Emitting `public.` unconditionally produced
    // `ALTER FUNCTION public.get_priv()` for a function created as `app.get_priv`,
    // which pglite answered with 42883 function public.get_priv() does not exist;
    // the REVOKE line carried the same defect. `target` reuses the source's own
    // spelling — including its quoting and case — so whatever the CREATE could
    // write, the ALTER can write. An UNQUALIFIED create yields an unqualified
    // target on purpose: it resolved through the migration runner's search_path
    // and the ALTER will resolve the same way. Guessing `public` there is how the
    // bug got in.
    const schemaMatch = /^("(?:[^"]|"")*"|[a-z0-9_$]+)\s*\./i.exec(starts[i].name);
    const schema = schemaMatch
      ? schemaMatch[1].replace(/^"([\s\S]*)"$/, '$1').replace(/""/g, '"')
      : null;
    const target = starts[i].name;

    const volatility = /\bimmutable\b/.test(header) ? 'immutable'
      : /\bstable\b/.test(header) ? 'stable'
        : /\bvolatile\b/.test(header) ? 'volatile' : null;

    const body = extractFunctionBody(segment);
    // Declared volatility is NOT proof the function cannot write. Postgres blocks
    // DML written directly in a non-volatile body, but a STABLE function that
    // calls a VOLATILE helper writes perfectly well — verified, the row landed.
    // So STABLE means "no DIRECT DML", never "cannot write", and the body still
    // has to be read.
    const directDml = body !== null
      ? bodyMutates(body)
      : /\b(insert\s+into|delete\s+from|update\s+[a-z_"])/.test(header);
    const nonVolatile = volatility === 'stable' || volatility === 'immutable';
    // A non-volatile function cannot successfully run direct DML, so a direct
    // hit there is dead code rather than a live mutation. What it CAN do is
    // reach a volatile helper, and that is unknowable from this file alone —
    // reported as a separate, softer signal so it never drives the REVOKE advice
    // that took a database down in 0.26.0.
    const mutates = nonVolatile ? false : directDml;
    const callsUserFunction = body !== null && bodyCallsUserFunction(body);

    const searchPath = functionSearchPath(segment);
    out.push({
      name,
      schema,
      target,
      isDefiner: /security\s+definer/.test(header),
      returnsTrigger: /returns\s+trigger/.test(header),
      mutates,
      // STABLE/IMMUTABLE + a call out to another function: Postgres will not stop
      // it writing through that callee. Not a violation on its own; surfaced so
      // the volatility claim is not mistaken for a proof.
      mutationUnknown: nonVolatile && callsUserFunction,
      volatility,
      bodyKnown: body !== null,
      searchPath,
      // Pinned to a path that reaches `public` first is not pinned in any way
      // that helps — see searchPathReachesPublicFirst.
      searchPathPinned: searchPath !== null && !searchPathReachesPublicFirst(searchPath),
    });
  }
  return out;
}

/**
 * The `SET search_path` clause on a `CREATE FUNCTION`, if it has one.
 *
 * Read from the HEADER only. A plpgsql body can contain its own
 * `set search_path` statement, which is a different thing entirely — it runs at
 * call time and does not attach to the function — so the segment is cut at the
 * body marker (`AS $tag$`, `AS '...'`, `BEGIN ATOMIC`) before matching.
 *
 * Returns the schema list, or null when the function is not pinned at all.
 */
export function functionSearchPath(segment) {
  const text = stripSqlComments(String(segment ?? ''));
  const bodyAt = text.search(/\bas\s*(?:\$[a-z0-9_]*\$|'|begin\s+atomic)/i);
  const header = bodyAt > 0 ? text.slice(0, bodyAt) : text;

  const m = header.match(
    /\bset\s+search_path\s*(?:=|\bto\b)\s*((?:"[^"]*"|[a-z0-9_$]+)(?:\s*,\s*(?:"[^"]*"|[a-z0-9_$]+))*)/i,
  );
  if (!m) return null;
  return m[1]
    .split(',')
    .map((x) => x.trim().replace(/^"(.*)"$/, '$1'))
    .filter(Boolean);
}

/**
 * Is a pinned path one that actually protects the function?
 *
 * Statically we cannot know which roles hold CREATE, so this answers the
 * narrower question that does not need a database: does resolution reach
 * `public` before it reaches anything else? That is the shape proven not to
 * protect — a definer function pinned `SET search_path = public, app`, with
 * `public` writable, returned an attacker's planted table. And `public` is
 * writable by default on Postgres 14 and earlier, where `CREATE` on it is
 * granted to `PUBLIC` out of the box (changed in 15).
 *
 * `pg_catalog` first is the canonical safe pin: it cannot be planted in, and
 * resolution stops being hijackable once it reaches a schema nobody can write.
 */
export function searchPathReachesPublicFirst(schemas) {
  for (const raw of schemas ?? []) {
    const schema = String(raw).toLowerCase();
    if (schema === 'pg_catalog') return false;
    if (schema === 'public') return true;
    if (schema === '$user') continue; // resolves to the owner's own schema
    return false; // some other named schema resolves first
  }
  return false;
}

/**
 * Render a schema list back into something `SET search_path = …` accepts.
 *
 * `functionSearchPath` strips the quotes it parsed, so joining the list with
 * commas can produce SQL the server rejects: `$user` unquoted is a syntax error,
 * and a schema with a space in it is two schemas. An identifier that is already
 * a plain word is emitted VERBATIM — not lowercased, not quoted — because
 * quoting `App` would change what it resolves to (unquoted `App` folds to `app`,
 * `"App"` does not).
 */
export function renderSearchPath(schemas) {
  return (schemas ?? [])
    .map((raw) => {
      const s = String(raw);
      return /^[A-Za-z_][A-Za-z0-9_$]*$/.test(s) ? s : `"${s.replace(/"/g, '""')}"`;
    })
    .join(', ');
}

/**
 * Turn a pinned-but-useless path into one that holds, WITHOUT losing an entry.
 *
 * The rule is preserve-then-reorder, in that order of priority:
 *   - `pg_catalog` goes first: nobody can plant in it, so resolution stops being
 *     hijackable the moment it gets there.
 *   - every other schema the author named is kept, in its original relative
 *     order. Dropping one is not a hardening, it is an outage — measured in
 *     pglite, replacing a pin of `public, app` with `pg_catalog, public, pg_temp`
 *     turned a working call into 42P01 relation "thing" does not exist.
 *   - `public` moves BEHIND those schemas, because `public` is what a
 *     lower-privileged role can plant in (CREATE on it is granted to PUBLIC out
 *     of the box on Postgres 14 and earlier). Verified: with the attacker's
 *     `public.thing` present, `pg_catalog, public, pg_temp` returned PLANTED
 *     while `pg_catalog, app, public, pg_temp` returned REAL.
 *   - `pg_temp` goes last, named explicitly, or Postgres searches it FIRST.
 *
 * Reordering `public` backwards is not unconditionally safe and the caller must
 * say so: if the same relation name exists in two of the listed schemas, this
 * changes which one wins (verified — a `thing` in both schemas flipped from
 * public's row to app's). That is a change to review, not a drop-in.
 */
export function hardenedSearchPath(schemas) {
  const seen = new Set();
  const kept = [];
  for (const raw of schemas ?? []) {
    const s = String(raw);
    const k = s.toLowerCase();
    if (!s || seen.has(k)) continue;
    seen.add(k);
    kept.push(s);
  }
  const is = (s, w) => String(s).toLowerCase() === w;
  const named = kept.filter((s) => !is(s, 'pg_catalog') && !is(s, 'pg_temp'));
  return [
    'pg_catalog',
    ...named.filter((s) => !is(s, 'public')),
    ...named.filter((s) => is(s, 'public')),
    'pg_temp',
  ];
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

/**
 * Does the body call out to another function?
 *
 * Matters because `STABLE` is enforced on the statements in THIS body, not on
 * what it reaches: a `STABLE` function that does `PERFORM helper()` where the
 * helper is `VOLATILE` writes without complaint. Verified — the row landed.
 *
 * Built-ins and the obvious read-only helpers are excluded, or every RLS
 * predicate in the schema would match. This is a signal for a note, never for a
 * violation, so a loose match here costs a sentence rather than a wrong REVOKE.
 */
export function bodyCallsUserFunction(body) {
  const text = stripSqlComments(String(body ?? '')).toLowerCase();
  const BUILTIN = new Set([
    'coalesce', 'nullif', 'greatest', 'least', 'count', 'sum', 'min', 'max', 'avg',
    'now', 'current_setting', 'set_config', 'concat', 'format', 'array_agg', 'jsonb_build_object',
    'json_build_object', 'to_jsonb', 'exists', 'lower', 'upper', 'trim', 'length', 'cast',
    'uid', 'jwt', 'role', 'email', 'nextval', 'currval', 'gen_random_uuid', 'random',
    'if', 'while', 'for', 'case', 'return', 'select', 'values', 'and', 'or', 'not', 'in', 'any', 'all',
  ]);
  for (const m of text.matchAll(/([a-z_][a-z0-9_]*)\s*\(/g)) {
    const name = m[1].includes('.') ? m[1].split('.').pop() : m[1];
    if (!BUILTIN.has(name)) return true;
  }
  return false;
}

/** The SECURITY DEFINER functions in `sql` (a filtered view of extractFunctionDefs). */
export function extractDefinerFunctions(sql) {
  return extractFunctionDefs(sql)
    .filter((f) => f.isDefiner)
    .map(({ isDefiner, ...f }) => f); // eslint-disable-line no-unused-vars
}

/** Does `sql` revoke EXECUTE on function `name` from PUBLIC or anon? */
/**
 * Parse a file once, or reuse a parse the caller already did.
 *
 * `run()` used to walk the same migration set five times: extractFunctionDefs in
 * findDefinerGrantViolations, findUnpinnedDefiners, findRlsHelpers and again for
 * the volatility notes, plus policyReferencedFunctions twice. Measured on a real
 * 204-file corpus that repetition is only ~24 ms, so this is the small half of
 * the cost — but it is free to remove and the finders keep their old signatures,
 * so the unit tests that call them with plain `{name, sql}` arrays still work.
 */
function defsOf(file) {
  return file?.defs ?? extractFunctionDefs(file?.sql ?? '');
}

function policyFnsOf(file) {
  return file?.policyFns ?? policyReferencedFunctions(file?.sql ?? '');
}

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
/**
 * A pinned path that never names `pg_temp` is incomplete, whatever else is on it.
 *
 * Postgres searches `pg_temp` BEFORE every schema you list unless you name it,
 * and `TEMP` on the database is granted to `PUBLIC` by default — so a temp table
 * shadows an unqualified name inside the function with no CREATE privilege
 * anywhere. Measured: `pg_catalog, app` ran the attacker's temp table;
 * `pg_catalog, app, pg_temp` ran the real one.
 */
export function omitsTempSchema(schemas) {
  const list = schemas ?? [];
  if (!list.length) return false; // unpinned is a separate, louder finding
  return !list.some((x) => String(x).toLowerCase() === 'pg_temp');
}

/**
 * SECURITY DEFINER functions whose `search_path` is not pinned to a path that
 * protects them — reported as NOTES, deliberately.
 *
 * Whether this is exploitable depends on who holds CREATE, which no static read
 * of migrations can answer: `definer-rpc` proves it against a real database, and
 * `create-grants` reports the precondition. What this adds is that it needs
 * nothing at all — it shows up on the pull request that introduces the function,
 * in a repository that has never wired up a test database.
 *
 * Returns { unpinned, publicFirst, noTemp, pinned } so the ones that DO pin
 * correctly can be counted rather than silently ignored.
 */
export function findUnpinnedDefiners(files, { baseline = 0, allowlist = [] } = {}) {
  const skip = new Set(allowlist);
  const unpinned = [], publicFirst = [], noTemp = [], pinned = [];

  for (const file of [...(files ?? [])].sort(compareMigrations)) {
    if (migrationNumber(file.name) <= baseline) continue;
    for (const fn of defsOf(file)) {
      if (!fn.isDefiner || fn.returnsTrigger) continue; // a trigger has no caller path to hijack
      if (skip.has(fn.name)) continue;
      const at = {
        name: fn.name, file: file.name, searchPath: fn.searchPath,
        // What an ALTER FUNCTION has to name. See extractFunctionDefs.
        schema: fn.schema ?? null, target: fn.target ?? fn.name,
      };
      if (fn.searchPath === null) unpinned.push(at);
      else if (!fn.searchPathPinned) publicFirst.push(at);
      else if (omitsTempSchema(fn.searchPath)) noTemp.push(at);
      else pinned.push(at);
    }
  }
  return { unpinned, publicFirst, noTemp, pinned };
}

export function findDefinerGrantViolations(files, { baseline = 0, allowlist = [] } = {}) {
  const allow = new Set(allowlist);
  const sorted = [...files].sort(compareMigrations);

  // The latest definition of each function name across all history.
  const latest = new Map(); // name -> { isDefiner, returnsTrigger, mutates, file, num }
  for (const file of sorted) {
    const num = migrationNumber(file.name);
    for (const fn of defsOf(file)) {
      latest.set(fn.name, { ...fn, file: file.name, num });
    }
  }

  // Is EXECUTE ever revoked from PUBLIC/anon for a name, anywhere in history?
  // CREATE OR REPLACE preserves grants, so a revoke that appears at all keeps it
  // revoked — the "fixed later in a repair migration" case.
  //
  // This loop is names x files, and it used to re-lowercase every migration's
  // FULL TEXT on every pair: `revokesAnonExecute` lowercases internally, so a
  // 204-file / 90-name corpus did 18,360 whole-file lowercasings and this one
  // loop was the clear majority of the guard's runtime (measured 409-830 ms out
  // of 827 ms; the entire parse pass was 12 ms). `.some()` short-circuits, so
  // the worst case is precisely the names that are NOT revoked — the ones that
  // get reported.
  //
  // The hoist below changes no result and deliberately does NOT touch the
  // matcher. `revokesAnonExecute`'s regex is name-anchored and gap-tolerant
  // (`revoke … on function … <name> … from … public|anon`), which is what makes
  // `REVOKE EXECUTE ON FUNCTION public.a(uuid), public.b(uuid) FROM PUBLIC, anon;`
  // count for both a and b. Rewriting it to harvest names out of REVOKE
  // statements would turn every name form it failed to harvest into a guard that
  // fires on a migration that DID revoke — the cry-wolf failure this tool must
  // not have. So: lower each file ONCE (idempotent, the matcher lowercases
  // anyway) and drop the files with no `revoke` substring at all (the regex is
  // anchored on that literal, so such a file can never match). Synthetic
  // 400 files x 800 functions: 463 ms -> 3 ms, byte-identical violations.
  const revokeTexts = [];
  for (const { sql } of sorted) {
    const lower = String(sql ?? '').toLowerCase();
    if (lower.includes('revoke')) revokeTexts.push(lower);
  }
  const revoked = new Set();
  if (revokeTexts.length > 0) {
    for (const name of latest.keys()) {
      if (revokeTexts.some((sql) => revokesAnonExecute(sql, name))) revoked.add(name);
    }
  }

  // Functions used inside a policy expression, anywhere in history. Postgres
  // requires the CALLING role to hold EXECUTE on these even when they are
  // SECURITY DEFINER, so revoking from PUBLIC breaks every read the policy
  // guards. They can never carry a revoke recommendation.
  const rlsHelpers = new Set();
  for (const file of sorted) {
    for (const n of policyFnsOf(file)) rlsHelpers.add(n);
  }

  // Violation only when the FINAL definition is a mutating, non-trigger
  // SECURITY DEFINER function above the baseline, never revoked, not allowlisted.
  const violations = [];
  for (const [name, def] of latest) {
    if (!def.isDefiner || def.returnsTrigger || !def.mutates) continue;
    if ((def.num ?? 0) <= baseline) continue;
    if (allow.has(name)) continue;
    if (revoked.has(name)) continue;
    violations.push({
      file: def.file,
      fn: name,
      // The spelling a REVOKE has to use — `public.` was hardcoded here and
      // errored 42883 on any function created in another schema.
      target: def.target ?? name,
      rlsHelper: rlsHelpers.has(name.toLowerCase()),
    });
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
  for (const file of sorted) for (const n of policyFnsOf(file)) referenced.add(n);

  const latest = new Map();
  for (const file of sorted) {
    const num = migrationNumber(file.name);
    for (const fn of defsOf(file)) latest.set(fn.name, { ...fn, file: file.name, num });
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
  // Parse each migration ONCE and carry the result. The finders fall back to
  // parsing when these fields are absent, so calling them directly with plain
  // `{name, sql}` objects (as the unit tests do) behaves identically.
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .map((f) => {
      const sql = readFileSync(join(dir, f), 'utf8');
      return { name: f, sql, defs: extractFunctionDefs(sql), policyFns: policyReferencedFunctions(sql) };
    });
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
      // Two things this line used to get wrong, both of which make it error
      // rather than help:
      //  - `public.` was hardcoded, so a function created as `app.get_priv`
      //    produced 42883 function public.get_priv() does not exist (pglite).
      //  - `FROM PUBLIC, anon` names a role that only exists on Supabase. On a
      //    plain Postgres the whole statement aborts with 42704 role "anon" does
      //    not exist, so the revoke does not happen at all. Revoking from PUBLIC
      //    is what actually closes this — the grant lives on PUBLIC and anon
      //    inherits it, which is the entire premise of this guard — so PUBLIC
      //    alone is both sufficient and portable. A DIRECT grant to anon is the
      //    one case that needs more, and that is what the second line is for.
      fix:
        `In the SAME migration add:  REVOKE EXECUTE ON FUNCTION ${v.target}(<args>) FROM PUBLIC;\n` +
        `      That is the one that matters: the default grant lives on PUBLIC and anon inherits it, so revoking from anon alone is a no-op.\n` +
        `      If your project ALSO granted EXECUTE directly to anon/authenticated, revoke from those roles too (naming them unconditionally fails with 42704 on a non-Supabase database).\n` +
        `      If it is intentionally pre-auth, add "${v.fn}" to definerGrants.allowlist[] in your tenant-guard config.`,
    }));

  const volatilityNotes = [];
  // Non-volatile definer functions that reach another function: the volatility
  // says nothing about what the callee does.
  for (const file of [...files].sort(compareMigrations)) {
    if (migrationNumber(file.name) <= baseline) continue;
    for (const fn of defsOf(file)) {
      if (!fn.isDefiner || fn.returnsTrigger || !fn.mutationUnknown) continue;
      if ((config.allowlist ?? []).includes(fn.name)) continue;
      volatilityNotes.push({
        where: file.name,
        message:
          `"${fn.name}" is SECURITY DEFINER and declared ${fn.volatility}, and it calls another function. ${fn.volatility?.toUpperCase()} only stops DML written in THIS body — a call out to a VOLATILE function writes without complaint, verified. So the volatility does not prove this function cannot mutate; check what it calls.`,
      });
    }
  }

  // ── search_path, statically ────────────────────────────────────────
  // Notes rather than failures on purpose: whether an unpinned path is
  // EXPLOITABLE depends on who holds CREATE, which migrations cannot tell you.
  // `definer-rpc` proves it against a database and `create-grants` reports the
  // precondition; the value here is that it needs neither, so it lands on the
  // pull request that introduces the function.
  const sp = findUnpinnedDefiners(files, { baseline, allowlist: config.allowlist ?? [] });
  const spNotes = [];

  for (const fn of sp.publicFirst) {
    // Build the replacement path FROM the one the author wrote. The old string
    // was a hardcoded `pg_catalog, public, pg_temp` that ignored fn.searchPath
    // entirely, and on a pin of `public, app` it did both possible wrong things
    // at once (measured in pglite, plpgsql body, plant made before the first
    // call): with the attacker's public.thing present the "fixed" function
    // returned PLANTED, and with it absent the function returned 42P01 relation
    // "thing" does not exist. The preserve-and-reorder path returned the real
    // row in both states.
    const hardened = hardenedSearchPath(fn.searchPath);
    const moved = hardened.filter(
      (s) => !['pg_catalog', 'pg_temp', 'public'].includes(String(s).toLowerCase()),
    );
    spNotes.push({
      where: fn.file,
      message:
        `"${fn.name}" is SECURITY DEFINER and pins search_path = ${renderSearchPath(fn.searchPath)} — which resolves through "public" first, so the pin protects nothing. ` +
        `Verified against a real database: a definer function pinned this way returned a table planted by a lower-privileged role; the same function with its own schema first returned the real one. ` +
        `On Postgres 14 and earlier "public" is writable by every role out of the box (CREATE is granted to PUBLIC by default; changed in 15).`,
      fix:
        `Keep every schema it already names, put one nobody can plant in first, and name pg_temp so it is searched last:\n` +
        `      ALTER FUNCTION ${fn.target}(<args>) SET search_path = ${renderSearchPath(hardened)};\n`
        + (moved.length > 0
          ? `      Review before applying: this moves "public" BEHIND ${moved.map((s) => `"${s}"`).join(', ')}. `
            + `If the same relation name exists in more than one of those schemas the function will now read a different one — verified, a table present in both flipped which row came back.`
          : `      Nothing is dropped or reordered relative to the schemas it reads; this only adds pg_catalog in front and pg_temp behind.`),
    });
  }

  for (const fn of sp.noTemp ?? []) {
    spNotes.push({
      where: fn.file,
      message:
        `"${fn.name}" is SECURITY DEFINER and pins search_path = ${fn.searchPath.join(', ')}, which does not name pg_temp — so the pin is incomplete. ` +
        `Postgres searches pg_temp BEFORE every schema you list unless you name it, and TEMP on the database is granted to PUBLIC by default, so a temp table shadows an unqualified name inside the function with no CREATE privilege needed anywhere. ` +
        `Measured: pinned "pg_catalog, app" the function ran a planted temp table; with pg_temp named last it ran the real one.`,
      // This bucket already preserved the path; only the hardcoded `public.`
      // qualifier and the unquoted join needed fixing.
      fix: `ALTER FUNCTION ${fn.target}(<args>) SET search_path = ${renderSearchPath([...fn.searchPath, 'pg_temp'])};`,
    });
  }

  for (const fn of sp.unpinned) {
    // There is no path to preserve here, so the suggestion is a STARTING POINT,
    // not a drop-in, and it has to say so: a pin REPLACES the caller's path, and
    // any unqualified name that used to resolve through it now fails with 42P01
    // if its schema is not listed. The best guess available statically is the
    // schema the function itself was created in.
    const own = fn.schema && String(fn.schema).toLowerCase() !== 'public' ? [fn.schema] : [];
    const suggested = hardenedSearchPath([...own, 'public']);
    spNotes.push({
      where: fn.file,
      message:
        `"${fn.name}" is SECURITY DEFINER with no SET search_path. Unqualified names inside it resolve through the CALLER's path, so a caller who can create objects makes it operate on THEIRS — running as the owner, with RLS bypassed. ` +
        `Whether anyone can is not visible from migrations: run \`tenant-guard rpc\` against a database to settle it, and \`tenant-guard creates\` for the CREATE grants that are the precondition.`,
      fix:
        `ALTER FUNCTION ${fn.target}(<args>) SET search_path = ${renderSearchPath(suggested)};\n` +
        `      Check that list against the body first — a pin REPLACES the caller's path, so every schema this function reads unqualified has to be named or the call fails with 42P01 relation … does not exist. ` +
        `Add them BEFORE "public", which is the one a lower-privileged role can plant in.`,
    });
  }

  if (sp.pinned.length > 0 && (sp.unpinned.length > 0 || sp.publicFirst.length > 0 || (sp.noTemp ?? []).length > 0)) {
    // The ones that got it right, counted rather than passed over in silence —
    // a report that only ever lists failures reads as if nothing is working.
    spNotes.push({
      where: '(search_path)',
      message: `${sp.pinned.length} other SECURITY DEFINER function(s) pin search_path to a path that holds. That is the pattern to copy.`,
    });
  }

  // The safe, common pattern, named so it reads as recognised rather than missed.
  const notes = findRlsHelpers(files, { baseline })
    .filter((h) => !h.mutates)
    .map((h) => ({
      where: h.file,
      message:
        `"${h.fn}" is a SECURITY DEFINER ${h.volatility ?? 'non-mutating'} predicate referenced by a policy — an RLS helper, which is the correct pattern. ` +
        `Not flagged, and its EXECUTE grant must stay: revoking it would break every read the policy guards.`,
    }))
    .concat(spNotes)
    .concat(volatilityNotes);

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
