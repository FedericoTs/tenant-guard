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
 *     EARLIER references an object a LATER one creates. That does not merely
 *     apply in a surprising order; it does not apply at all. Conclusive.
 *
 * Everything else about a tie is reported as a note, including the case where
 * lexicographic order disagrees with the numbering (`9_x.sql` after `10_y.sql`)
 * — the filenames and the numbers say different things, and both this tool and
 * the migration runner follow the filenames.
 *
 * Pure helpers below have no I/O so they are trivially unit-testable; `run()`
 * does the filesystem read. Zero dependencies (node builtins only).
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { stripSqlComments, compareMigrations, lexicographicDisagreesWithNumeric } from './definer-grants.mjs';

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
    .map(([number, files]) => ({ number, files: [...files].sort() }))
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

/** Objects a migration READS or depends on. */
export function referencedObjects(sql) {
  const text = stripSqlComments(sql);
  const out = new Set();
  const re = /\b(?:from|join|references|alter\s+table(?:\s+if\s+exists)?|on|into|update)\s+(?:only\s+)?([a-z0-9_."]+)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const name = m[1].replace(/"/g, '').split('.').pop().toLowerCase();
    if (name && !/^(select|values|table|conflict|delete|set)$/.test(name)) out.add(name);
  }
  return out;
}

/**
 * Within a tied group, does a migration that sorts EARLIER depend on an object a
 * LATER one creates? That is not a surprising order — it is a migration that
 * cannot apply.
 * @param {{name:string, sql:string}[]} group  already sorted the way they apply
 */
export function findDependencyInversions(group) {
  const inversions = [];
  const created = group.map((f) => createdObjects(f.sql));
  const referenced = group.map((f) => referencedObjects(f.sql));
  for (let i = 0; i < group.length; i++) {
    for (let j = i + 1; j < group.length; j++) {
      for (const obj of referenced[i]) {
        // Something the earlier file uses but does not itself create, and the
        // later file does.
        if (created[j].has(obj) && !created[i].has(obj)) {
          inversions.push({ earlier: group[i].name, later: group[j].name, object: obj });
        }
      }
    }
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

  const violations = [];
  const notes = [];

  for (const c of detectCollisions(filenames)) {
    // Sorted the way the migration runner will actually apply them.
    const group = c.files
      .map((name) => ({ name, sql: readFileSync(join(dir, name), 'utf8') }))
      .sort(compareMigrations);

    const inversions = findDependencyInversions(group);
    if (inversions.length > 0 && !grandfather.has(c.number)) {
      for (const inv of inversions) {
        violations.push({
          where: `${inv.earlier}, ${inv.later}`,
          kind: 'dependency-inversion',
          message:
            `these migrations share the prefix ${c.number}, and "${inv.earlier}" — which applies FIRST in ` +
            `lexicographic filename order — references "${inv.object}", which "${inv.later}" creates. ` +
            `That is not a surprising order; it is a migration that cannot apply against a fresh database.`,
          fix:
            `Renumber "${inv.later}" so it applies before "${inv.earlier}", or move the reference.\n` +
            `      Verify with a migration run against an EMPTY database — an existing one already has "${inv.object}", ` +
            `which is why this passes locally.`,
        });
      }
      continue;
    }

    if (!grandfather.has(c.number)) {
      notes.push({
        where: c.files.join(', '),
        message:
          `${c.files.length} migrations share the prefix ${c.number}. Their apply order is still deterministic — ` +
          `migrations run in lexicographic FULL-FILENAME order — and nothing in them depends on the other, so this ` +
          `is a naming choice rather than a hazard. Reported so a rename cannot quietly reorder them.`,
      });
    }
  }

  if (lexicographicDisagreesWithNumeric(filenames)) {
    notes.push({
      where: '(numbering)',
      message:
        `sorting these filenames lexicographically gives a different order from sorting them by numeric prefix, ` +
        `which happens with unpadded numbers ("9_x.sql" sorts AFTER "10_y.sql"). Migrations apply in filename order, ` +
        `so the filenames win — pad the numbers so the two agree and the order reads the way it runs.`,
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
