/**
 * Guard: migrations whose apply ORDER is ambiguous or wrong.
 *
 * This used to fail on any shared numeric prefix. That is too strict, and it
 * was reported failing a real repository on eleven historical same-DATE groups:
 * Supabase and friends apply migrations in **lexicographic full-filename**
 * order, so `20260531_a.sql` deterministically precedes `20260531_b.sql`. A
 * shared prefix alone is a naming choice, not a hazard — and a guard that fails
 * on it hands date-prefixed repos (a common convention) a large grandfather list
 * on their first run, which is how a tool stops being trusted.
 *
 * What IS a hazard, and what this fails on now:
 *
 *   - **Dependency inversion.** Within a tied group, a migration that sorts
 *     EARLIER references an object a LATER one creates, AND no earlier migration
 *     in the repo already created it. That does not merely apply in a surprising
 *     order; it does not apply at all. Conclusive.
 *
 * Everything else about a tie is reported as a note, including the case where
 * lexicographic order disagrees with the numbering (`9_x.sql` after `10_y.sql`)
 * — the filenames and the numbers say different things, and which one wins is a
 * property of the runner, not of the files.
 *
 * Three calibration fixes are recorded inline below, each reproduced against
 * PGlite on an EMPTY database before and after: ICU vs code-unit filename order,
 * plpgsql bodies that are not name-resolved at CREATE time, and objects an
 * EARLIER migration already created. All three were failing builds on migrations
 * that apply cleanly.
 *
 * Pure helpers below have no I/O so they are trivially unit-testable; `run()`
 * does the filesystem read. Zero dependencies (node builtins only).
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { stripSqlComments, extractFunctionBody, migrationNumber } from './definer-grants.mjs';

/**
 * Order migrations the way the tools that apply them do: by FULL FILENAME,
 * comparing UTF-16 CODE UNITS. That is `readdirSync().sort()`, Go
 * `sort.Strings`, Java `String.compareTo`, `ls` under LC_ALL=C — every migration
 * runner that sorts filenames.
 *
 * Deliberately NOT `localeCompare`. ICU collation folds case and gives
 * punctuation a lower weight than letters, so it orders a tied group backwards
 * on ordinary names. Measured on this repo's node (full ICU, 'en'):
 *
 *   '0012_Vendors.sql' vs '0012_add_note.sql'  locale +1, code-unit -1
 *   '0001_x1.sql'      vs '0001_x_1.sql'       locale +1, code-unit -1
 *
 * Consequence, verified in PGlite against a brand-new database:
 * `20260531_API_keys_table.sql` (CREATE TABLE) + `20260531_add_rls.sql` (ALTER
 * … ENABLE ROW LEVEL SECURITY) apply OK/OK in code-unit order — the order the
 * runner uses — and fail with `relation "public.api_keys" does not exist` only
 * in ICU order. The guard was reporting a `dependency-inversion` build failure
 * against migrations that apply cleanly. The mirror image was also real:
 * `0002_x1.sql` reading a table `0002_x_1.sql` creates DOES fail on a fresh
 * database and the guard passed it.
 *
 * `detectCollisions` below always sorted by code unit, so before this the group
 * printed in one order and was analysed in the opposite one.
 */
export function compareByFilename(a, b) {
  const x = String(a?.name ?? a);
  const y = String(b?.name ?? b);
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * Does filename order disagree with the numbering? That happens with UNPADDED
 * numbering (`9_x.sql` sorts after `10_y.sql`), where the filenames say one
 * thing and the numbers another.
 *
 * Local rather than imported so it is computed with the same code-unit order the
 * rest of this file analyses in; `definer-grants.mjs` still exports a
 * `localeCompare` version used by other guards.
 */
export function filenameOrderDisagreesWithNumbering(filenames) {
  const sql = [...(filenames ?? [])].filter((f) => f.endsWith('.sql'));
  const byName = [...sql].sort(compareByFilename);
  const byNumber = [...sql].sort((a, b) => {
    const d = (migrationNumber(a) ?? 0) - (migrationNumber(b) ?? 0);
    return d !== 0 ? d : compareByFilename(a, b);
  });
  return byName.some((f, i) => f !== byNumber[i]);
}

/** Group migration filenames by leading numeric prefix; return only the dups. */
export function detectCollisions(filenames) {
  const byNumber = {};
  for (const f of filenames) {
    if (!f.endsWith('.sql')) continue;
    const m = f.match(/^(\d+)/);
    if (!m) continue;
    (byNumber[m[1]] ??= []).push(f);
  }
  return Object.entries(byNumber)
    .filter(([, files]) => files.length > 1)
    .map(([number, files]) => ({ number, files: [...files].sort(compareByFilename) }))
    .sort((a, b) => a.number.localeCompare(b.number));
}

/** Collisions that are NOT in the grandfathered allowlist (i.e. real failures). */
export function findNewCollisions(filenames, grandfathered = []) {
  const allow = new Set(grandfathered.map(String));
  return detectCollisions(filenames).filter((c) => !allow.has(c.number));
}

/** Objects a migration CREATEs, lower-cased and unqualified. */
export function createdObjects(sql) {
  const text = stripSqlComments(sql);
  const out = new Set();
  const re = /create\s+(?:or\s+replace\s+)?(?:unique\s+)?(?:materialized\s+)?(table|view|function|index|type|sequence|schema|trigger)\s+(?:if\s+not\s+exists\s+)?([a-z0-9_."]+)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.add(m[2].replace(/"/g, '').split('.').pop().toLowerCase());
  }
  return out;
}

/**
 * Split a migration into the text Postgres name-resolves AT APPLY TIME and the
 * function bodies it does not.
 *
 * Measured in PGlite on an empty database, `check_function_bodies` = on:
 *
 *   LANGUAGE sql    AS $$ SELECT count(*) FROM public.nope $$        -> FAILED
 *   LANGUAGE sql    BEGIN ATOMIC SELECT count(*) FROM public.nope;   -> FAILED
 *   LANGUAGE plpgsql AS $$ BEGIN RETURN (SELECT … public.nope); END $$ -> CREATED OK
 *   LANGUAGE plpgsql AS $$ BEGIN INSERT INTO public.nope …; END $$     -> CREATED OK
 *
 * So a `sql` body is fully analysed at CREATE and a plpgsql body is only
 * syntax-checked. Counting names inside a plpgsql body as apply-time
 * dependencies failed builds on the ordinary Supabase layout of one date-prefixed
 * `_helpers.sql` defining `current_org()` plus a `_tables.sql` creating
 * `memberships` — verified applying OK/OK against an empty database while the
 * guard reported "a migration that cannot apply against a fresh database".
 *
 * Only the BODY is removed — the signature and everything outside it stay, so
 * `CREATE TRIGGER … ON later_tbl` and every top-level statement still count.
 * (`RETURNS SETOF later_tbl` does fail at CREATE even for plpgsql, but the
 * reference regex never matched `returns setof` in the first place, so nothing
 * is lost here that was detected before.)
 *
 * Two deliberate refusals to blank:
 *   - unknown language, or a body `extractFunctionBody` cannot find — "unknown"
 *     must never become "safe";
 *   - a function the same migration CALLS at top level (`SELECT f()`, `PERFORM`,
 *     `CALL`), because then the body really does run during that migration.
 *     `EXECUTE FUNCTION f()` inside a CREATE TRIGGER is not such a call — the
 *     body runs on later DML — so it is excluded from that test.
 *
 * @returns {{code: string, deferred: string[]}}
 */
export function splitDeferredBodies(sql) {
  const text = stripSqlComments(sql);
  const re = /create\s+(?:or\s+replace\s+)?function\s+([a-z0-9_."]+)\s*\(/gi;
  const starts = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    starts.push({ index: m.index, name: m[1].replace(/"/g, '').split('.').pop().toLowerCase() });
  }
  if (starts.length === 0) return { code: text, deferred: [] };

  const segments = starts.map((s, i) => {
    const start = s.index;
    const end = i + 1 < starts.length ? starts[i + 1].index : text.length;
    const segment = text.slice(start, end);
    const body = extractFunctionBody(segment);
    const at = body && body.length > 0 ? segment.indexOf(body) : -1;
    return { name: s.name, start, end, segment, body, at };
  });

  // Where a top-level call would live: the whole migration with every function
  // BODY removed (a call from inside another body does not run at apply time
  // either), and with the two shapes that only LOOK like calls removed —
  // `CREATE FUNCTION f(...)` is the definition, `EXECUTE FUNCTION f()` inside a
  // CREATE TRIGGER is a binding that fires on later DML.
  let noBodies = '';
  let prev = 0;
  for (const s of segments) {
    noBodies += text.slice(prev, s.start);
    noBodies += s.at === -1 ? s.segment : s.segment.slice(0, s.at) + ' \n ' + s.segment.slice(s.at + s.body.length);
    prev = s.end;
  }
  noBodies += text.slice(prev);
  const callable = noBodies
    .replace(/\bcreate\s+(?:or\s+replace\s+)?function\s+[a-z0-9_."]+\s*\([^)]*\)/gi, ' ')
    .replace(/\bexecute\s+(?:function|procedure)\s+[a-z0-9_."]+\s*\([^)]*\)/gi, ' ');

  const deferred = [];
  let code = text.slice(0, segments[0].start);
  for (const s of segments) {
    if (s.at === -1) { code += s.segment; continue; }

    const around = s.segment.slice(0, s.at) + ' \n ' + s.segment.slice(s.at + s.body.length);
    const lang = /\blanguage\s+([a-z0-9_]+)/i.exec(around);
    const called = new RegExp(`\\b(?:[a-z0-9_]+\\.)?${s.name}\\s*\\(`, 'i').test(callable);
    if (!lang || lang[1].toLowerCase() === 'sql' || called) { code += s.segment; continue; }

    deferred.push(s.body);
    code += around;
  }
  return { code, deferred };
}

/** The reference scan itself, over already-prepared text. */
function scanReferences(text) {
  const out = new Set();
  // The optional object-type prefix is matched HERE rather than left to the
  // keyword filter below. `GRANT SELECT ON TABLE public.t` used to capture the
  // literal word `table`, which the filter then dropped — losing the table name
  // entirely, while the identical statement written `ON public.t` was caught.
  // Verified in PGlite: both forms fail with `relation … does not exist` on an
  // empty database, and the guard failed only one of them.
  const re = /\b(?:from|join|references|alter\s+table(?:\s+if\s+exists)?|on|into|update)\s+(?:all\s+(?:tables|sequences|functions|routines)\s+in\s+schema\s+|only\s+|table\s+|sequence\s+|function\s+|procedure\s+|routine\s+|schema\s+|domain\s+|type\s+)?([a-z0-9_."]+)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const name = m[1].replace(/"/g, '').split('.').pop().toLowerCase();
    // Still needed: these are the genuine SQL keywords that `on`/`into`/`update`
    // sweep up — `ON CONFLICT`, `VALUES`, `DO UPDATE SET`.
    if (name && !/^(select|values|table|conflict|delete|set)$/.test(name)) out.add(name);
  }
  return out;
}

/** Objects a migration READS or depends on WHEN IT APPLIES. */
export function referencedObjects(sql) {
  return scanReferences(splitDeferredBodies(sql).code);
}

/**
 * Objects named only inside a function body that is not resolved at CREATE time.
 * The migration applies; the function is broken until the object exists. Worth
 * saying, never worth failing a build over.
 */
export function deferredReferencedObjects(sql) {
  const { code, deferred } = splitDeferredBodies(sql);
  if (deferred.length === 0) return new Set();
  const applyTime = scanReferences(code);
  const out = new Set();
  for (const o of scanReferences(deferred.join('\n;\n'))) if (!applyTime.has(o)) out.add(o);
  return out;
}

/**
 * Does a migration that sorts EARLIER depend on an object a LATER one creates?
 * That is not a surprising order — it is a migration that cannot apply.
 *
 * `priorCreated` is what the database already contains when the first file in
 * `group` runs. Without it, a group member that merely RE-declares an object
 * (`CREATE TABLE IF NOT EXISTS`, `CREATE OR REPLACE VIEW`) was scored as its
 * first creation, so an earlier sibling touching that object was reported as an
 * inversion. Verified: base migration creates `existing`; `0003_a_alter.sql`
 * alters it; `0003_b_idem.sql` re-declares it IF NOT EXISTS — all three apply
 * OK/OK/OK to a fresh PGlite database, and the guard failed the build. Filtering
 * on the IF NOT EXISTS keyword instead would have been wrong: the same fixture
 * WITHOUT a base migration genuinely fails (`relation "public.brandnew" does not
 * exist`), so the modifier says nothing about whether the object exists yet.
 *
 * @param {{name:string, sql:string}[]} group  already sorted the way they apply
 */
export function findDependencyInversions(group, { priorCreated = new Set(), referenced = referencedObjects } = {}) {
  const inversions = [];
  const created = group.map((f) => createdObjects(f.sql));
  const refs = group.map((f) => referenced(f.sql));
  // Objects that exist by the time group[i] runs.
  const seen = new Set(priorCreated);
  for (let i = 0; i < group.length; i++) {
    for (const obj of refs[i]) {
      if (seen.has(obj) || created[i].has(obj)) continue;
      for (let j = i + 1; j < group.length; j++) {
        if (created[j].has(obj)) {
          inversions.push({ earlier: group[i].name, later: group[j].name, object: obj });
          break;
        }
      }
    }
    for (const obj of created[i]) seen.add(obj);
  }
  return inversions;
}

export const meta = {
  id: 'migration-collisions',
  title: 'Migration number collisions',
  why: 'Two migrations sharing a numeric prefix can apply in either order; a rename can silently clobber one.',
};

/**
 * @param {object} config  guard config: { dir, grandfather?: string[] }
 * @returns {{ id, ok, skipped?, reason?, violations, scanned, summary }}
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
      notes: [],
      scanned: 0,
      summary: 'skipped',
    };
  }
  const filenames = readdirSync(dir).filter((f) => f.endsWith('.sql'));
  const grandfather = new Set((config.grandfather ?? []).map(String));

  const collisions = detectCollisions(filenames);
  const numberingDisagrees = !grandfather.has('(numbering)') && !grandfather.has('numbering')
    && filenameOrderDisagreesWithNumbering(filenames);

  // Read once, in apply order, and keep a running set of what the database
  // already contains at each point. A tied group is then judged against the
  // history in front of it rather than against itself alone. Skipped entirely
  // when there is nothing to judge, so a repo with no collisions still costs one
  // readdir and no file reads.
  const needsHistory = collisions.length > 0 || numberingDisagrees;
  const ordered = needsHistory
    ? [...filenames].sort(compareByFilename).map((name) => ({ name, sql: readFileSync(join(dir, name), 'utf8') }))
    : [];
  const createdBefore = new Map();
  const running = new Set();
  for (const f of ordered) {
    createdBefore.set(f.name, new Set(running));
    for (const obj of createdObjects(f.sql)) running.add(obj);
  }
  const sqlOf = new Map(ordered.map((f) => [f.name, f.sql]));

  const violations = [];
  const notes = [];

  for (const c of collisions) {
    // Sorted the way the migration runner will actually apply them.
    const group = c.files.map((name) => ({ name, sql: sqlOf.get(name) })).sort(compareByFilename);
    const priorCreated = createdBefore.get(group[0].name) ?? new Set();

    const inversions = findDependencyInversions(group, { priorCreated });
    if (inversions.length > 0 && !grandfather.has(c.number)) {
      for (const inv of inversions) {
        violations.push({
          where: `${inv.earlier}, ${inv.later}`,
          kind: 'dependency-inversion',
          message:
            `these migrations share the prefix ${c.number}, and "${inv.earlier}" — which applies FIRST in ` +
            `lexicographic filename order — references "${inv.object}", which "${inv.later}" creates. ` +
            `No earlier migration creates it either. That is not a surprising order; it is a migration that ` +
            `cannot apply against a fresh database.`,
          fix:
            `Renumber "${inv.later}" so it applies before "${inv.earlier}", or move the reference.\n` +
            `      Verify with a migration run against an EMPTY database — an existing one already has "${inv.object}", ` +
            `which is why this passes locally.`,
        });
      }
      continue;
    }

    if (grandfather.has(c.number)) continue;

    // Applies fine, but a function in the earlier file reads something only the
    // later one creates. Postgres does not resolve a plpgsql body at CREATE, so
    // this is not a failed migration — it is a function that is broken until the
    // later file runs. Reported, never failed on.
    const deferredInversions = findDependencyInversions(group, {
      priorCreated,
      referenced: deferredReferencedObjects,
    });
    if (deferredInversions.length > 0) {
      for (const inv of deferredInversions) {
        notes.push({
          where: `${inv.earlier}, ${inv.later}`,
          message:
            `"${inv.earlier}" defines a function whose body reads "${inv.object}", which "${inv.later}" creates. ` +
            `Both migrations apply — Postgres does not name-resolve a non-SQL function body at CREATE time ` +
            `(verified against an empty database) — but the function raises "relation does not exist" if it is ` +
            `called before "${inv.later}" has run.`,
        });
      }
      continue;
    }

    notes.push({
      where: c.files.join(', '),
      message:
        `${c.files.length} migrations share the prefix ${c.number}. Their apply order is still deterministic — ` +
        `migrations run in lexicographic FULL-FILENAME order — and nothing in them depends on the other, so this ` +
        `is a naming choice rather than a hazard. Reported so a rename cannot quietly reorder them.`,
    });
  }

  // Unpadded numbering: filename order and the numbering disagree. Which one is
  // real depends on the runner — Supabase/dbmate/`readdir().sort()` follow the
  // filenames, Flyway and golang-migrate follow the numbers — so this stays a
  // NOTE. What it did not used to do is say whether anything actually breaks:
  // `9_create_widgets.sql` + `10_use_widgets.sql` produced only "pad the
  // numbers", while applying them in filename order against an empty PGlite
  // database fails with `relation "public.widgets" does not exist`. That is
  // named now. It is deliberately not escalated to a violation: for a repo whose
  // runner sorts numerically the same files are correct, and failing a build on
  // correct code is the more expensive error.
  if (numberingDisagrees) {
    // Restricted to pairs the padding gap itself inverts (numbering says the
    // other way round) and to objects no earlier file creates. An unrestricted
    // whole-history scan with this loose a reference regex is where cry-wolf
    // lives.
    const crossings = findDependencyInversions(ordered).filter(
      (inv) => (migrationNumber(inv.earlier) ?? 0) > (migrationNumber(inv.later) ?? 0),
    );
    for (const inv of crossings) {
      notes.push({
        where: `${inv.earlier}, ${inv.later}`,
        message:
          `unpadded numbering: "${inv.later}" is numbered ${migrationNumber(inv.later)} and "${inv.earlier}" ` +
          `${migrationNumber(inv.earlier)}, so the numbers say "${inv.later}" runs first — but in filename order ` +
          `"${inv.earlier}" runs first and references "${inv.object}", which "${inv.later}" creates. A runner that ` +
          `sorts by FILENAME (Supabase, dbmate, readdir+sort) will fail to apply this against an empty database; ` +
          `one that sorts NUMERICALLY (Flyway, golang-migrate) will not. Zero-pad the numbers and the question ` +
          `stops existing.`,
      });
    }
    notes.push({
      where: '(numbering)',
      message:
        `sorting these filenames lexicographically gives a different order from sorting them by numeric prefix, ` +
        `which happens with unpadded numbers ("9_x.sql" sorts AFTER "10_y.sql"). Migrations apply in filename order, ` +
        `so the filenames win — pad the numbers so the two agree and the order reads the way it runs.` +
        (crossings.length ? ` ${crossings.length} dependency/dependencies actually cross that boundary; see above.` : ''),
    });
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned: filenames.length,
    summary:
      violations.length > 0
        ? `${violations.length} migration(s) reference an object a later migration creates`
        : `${filenames.length} migrations scanned` + (notes.length ? `; ${notes.length} note(s)` : ''),
  };
}
