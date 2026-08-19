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

/** Leading numeric prefix of a migration filename, or null. */
export function migrationNumber(filename) {
  const m = filename.match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

/**
 * Parse a migration's SQL into EVERY function it defines, with the properties
 * that decide safety. Heuristic (no full SQL parser): split on each
 * CREATE [OR REPLACE] FUNCTION and inspect the segment up to the next one.
 * Returns [{ name, isDefiner, returnsTrigger, mutates }].
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
    const lower = sql.slice(start, end).toLowerCase();
    const rawName = starts[i].name.replace(/"/g, '');
    const name = rawName.includes('.') ? rawName.split('.').pop() : rawName;
    out.push({
      name,
      isDefiner: /security\s+definer/.test(lower),
      returnsTrigger: /returns\s+trigger/.test(lower),
      mutates: /\b(insert|update|delete)\b/.test(lower),
    });
  }
  return out;
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
  const sorted = [...files].sort((a, b) => (migrationNumber(a.name) ?? 0) - (migrationNumber(b.name) ?? 0));

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

  // Violation only when the FINAL definition is a mutating, non-trigger
  // SECURITY DEFINER function above the baseline, never revoked, not allowlisted.
  const violations = [];
  for (const [name, def] of latest) {
    if (!def.isDefiner || def.returnsTrigger || !def.mutates) continue;
    if ((def.num ?? 0) <= baseline) continue;
    if (allow.has(name)) continue;
    if (revoked.has(name)) continue;
    violations.push({ file: def.file, fn: name });
  }
  return violations;
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

  const violations = raw.map((v) => ({
    where: v.file,
    message: `function "${v.fn}" is SECURITY DEFINER + mutates but EXECUTE is not revoked from PUBLIC/anon`,
    fix:
      `In the SAME migration add:  REVOKE EXECUTE ON FUNCTION public.${v.fn}(<args>) FROM PUBLIC, anon;\n` +
      `      If it is intentionally pre-auth, add "${v.fn}" to definerGrants.allowlist[] in your tenant-guard config.`,
  }));

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    scanned,
    summary:
      violations.length === 0
        ? `${scanned} migration(s) above baseline ${baseline} scanned; ${files.length} total`
        : `${violations.length} unsafe function(s)`,
  };
}
