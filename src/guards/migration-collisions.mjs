/**
 * Guard: migration number collisions.
 *
 * Two SQL migrations sharing the same leading numeric prefix create an
 * apply-order ambiguity — tooling can run them in either order, and a careless
 * rename can silently clobber one. This guard fails when a NEW collision is
 * introduced, while grandfathering numbers that already exist in history
 * (renaming an already-applied migration breaks the migration ledger).
 *
 * Pure helpers below have no I/O so they are trivially unit-testable; `run()`
 * does the filesystem read. Zero dependencies (node builtins only).
 */
import { readdirSync, existsSync } from 'node:fs';

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
      scanned: 0,
      summary: 'skipped',
    };
  }
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql'));
  const grandfather = config.grandfather ?? [];
  const fresh = findNewCollisions(files, grandfather);
  const grandfatheredHit = detectCollisions(files).filter((c) => new Set(grandfather.map(String)).has(c.number));

  const violations = fresh.map((c) => ({
    where: c.files.join(', '),
    message: `migration number ${c.number} used by ${c.files.length} files`,
    fix: `Renumber the NEW file to the next free number. If this is an intentional, already-applied historical duplicate, add "${c.number}" to grandfather[] in your tenant-guard config.`,
  }));

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    scanned: files.length,
    summary:
      violations.length === 0
        ? `${files.length} migrations scanned; ${grandfatheredHit.length} grandfathered duplicate(s) ignored`
        : `${violations.length} new collision(s)`,
  };
}
