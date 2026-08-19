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
import * as rlsDrift from './guards/rls-drift.mjs';
import * as anonWrites from './guards/anon-writes.mjs';
import * as anonReads from './guards/anon-reads.mjs';
import * as viewIsolation from './guards/view-isolation.mjs';
import * as identityTrust from './guards/identity-trust.mjs';
import * as storageIsolation from './guards/storage-isolation.mjs';
import { loadConfig, resolveGuardConfigs, resolveProveConfig, resolveDriftConfig, resolveAnonWritesConfig, resolveAnonReadsConfig, resolveViewIsolationConfig, resolveIdentityTrustConfig, resolveStorageConfig } from './config.mjs';

// The static guards: synchronous, zero-dependency, no database. These are what
// `tenant-guard run` executes and what a project's vitest/jest suite imports.
export const GUARDS = [migrationCollisions, definerGrants, routeOrgScoping];

export { migrationCollisions, definerGrants, routeOrgScoping, rlsProof, rlsDrift, anonWrites, anonReads, viewIsolation, identityTrust, storageIsolation };
export { prove } from './guards/rls-proof.mjs';
export { drift } from './guards/rls-drift.mjs';
export { check as checkAnonWrites } from './guards/anon-writes.mjs';
export { check as checkAnonReads } from './guards/anon-reads.mjs';
export { check as checkViews } from './guards/view-isolation.mjs';
export { check as checkIdentity } from './guards/identity-trust.mjs';
export { check as checkStorage } from './guards/storage-isolation.mjs';
export { loadConfig, resolveGuardConfigs, resolveProveConfig, resolveDriftConfig, resolveAnonWritesConfig, resolveAnonReadsConfig, resolveViewIsolationConfig, resolveIdentityTrustConfig, resolveStorageConfig } from './config.mjs';

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

/**
 * Run the RLS-drift check (async; needs a database URL + the `pg` driver, and
 * reads your migrations). Compares migration-declared RLS against the live
 * catalog. Returns a single guard result object.
 */
export async function runDrift(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return rlsDrift.run(resolveDriftConfig(config));
}

/**
 * Run the anon-write-surface check (async; needs a database URL + `pg`). Flags
 * tables the unauthenticated role can write. Returns a single guard result.
 */
export async function runAnonWrites(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return anonWrites.run(resolveAnonWritesConfig(config));
}

/**
 * Run the anon-read-surface check (async; needs a database URL + `pg`). Proves the
 * unauthenticated role cannot read tenant tables — the CVE-2025-48757 class.
 * Returns a single guard result.
 */
export async function runAnonReads(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return anonReads.run(resolveAnonReadsConfig(config));
}

/**
 * Run the view/materialized-view isolation proof (async; needs a database URL +
 * `pg`). Views run with their owner's rights unless security_invoker is set, and
 * RLS never applies to materialized views — neither is visible to a table-only
 * check. Returns a single guard result.
 */
export async function runViews(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return viewIsolation.run(resolveViewIsolationConfig(config));
}

/**
 * Run the identity-trust check (async; needs a database URL + `pg`). Asks whether
 * the caller can FORGE the identity your policies authorize from — user-writable
 * JWT claims, or a callable definer function that sets the tenant GUC from an
 * argument. Returns a single guard result.
 */
export async function runIdentity(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return identityTrust.run(resolveIdentityTrustConfig(config));
}

/**
 * Run the Supabase Storage isolation check (async; needs a database URL + `pg`).
 * Storage keys tenancy off the object PATH rather than a column, and the client
 * chooses that path on upload. Skips cleanly on non-Supabase databases.
 */
export async function runStorage(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return storageIsolation.run(resolveStorageConfig(config));
}
