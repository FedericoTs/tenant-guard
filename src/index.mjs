/**
 * tenant-guard programmatic API.
 *
 * Import individual guards and call run(config) yourself, or use runAll() to
 * run every guard against a resolved config. This is what a project's own
 * vitest/jest suite imports to make the guards part of `npm test`.
 */
import * as migrationCollisions from './guards/migration-collisions.mjs';
import * as definerGrants from './guards/definer-grants.mjs';
import * as routeOrgScoping from './guards/route-org-scoping.mjs';
import * as rlsProof from './guards/rls-proof.mjs';
import { loadConfig, resolveGuardConfigs, resolveProveConfig } from './config.mjs';

// The static guards: synchronous, zero-dependency, no database. These are what
// `tenant-guard run` executes and what a project's vitest/jest suite imports.
export const GUARDS = [migrationCollisions, definerGrants, routeOrgScoping];

export { migrationCollisions, definerGrants, routeOrgScoping, rlsProof };
export { prove } from './guards/rls-proof.mjs';
export { loadConfig, resolveGuardConfigs, resolveProveConfig } from './config.mjs';

/** Run every static guard against a resolved per-guard config map. Returns results[]. */
export function runAll(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  const perGuard = resolveGuardConfigs(config);
  return GUARDS.map((g) => g.run(perGuard[g.meta.id]));
}

/**
 * Run the runtime RLS proof (async; needs a database URL + the `pg` driver).
 * Kept separate from runAll() so `tenant-guard run` stays instant and hermetic
 * for every CI, while `tenant-guard prove` is the opt-in, DB-backed proof.
 * Returns a single guard result object.
 */
export async function runProof(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return rlsProof.run(resolveProveConfig(config));
}
