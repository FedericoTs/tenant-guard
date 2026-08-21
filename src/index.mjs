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
import * as constraintOracles from './guards/constraint-oracles.mjs';
import * as realtimeIsolation from './guards/realtime-isolation.mjs';
import * as definerRpc from './guards/definer-rpc.mjs';
import * as shadowTables from './guards/shadow-tables.mjs';
import * as roleCapabilities from './guards/role-capabilities.mjs';
import * as schemaTenancy from './guards/schema-tenancy.mjs';
import * as poolerBleed from './guards/pooler-bleed.mjs';
import * as defaultPrivileges from './guards/default-privileges.mjs';
import * as crossTenantFk from './guards/cross-tenant-fk.mjs';
import * as createGrants from './guards/create-grants.mjs';
import * as updatableViews from './guards/updatable-view-writethrough.mjs';
import { loadConfig, resolveGuardConfigs, resolveProveConfig, resolveDriftConfig, resolveAnonWritesConfig, resolveAnonReadsConfig, resolveViewIsolationConfig, resolveIdentityTrustConfig, resolveStorageConfig, resolveOraclesConfig, resolveRealtimeConfig, resolveDefinerRpcConfig, resolveShadowConfig, resolveCapabilitiesConfig, resolveSchemaTenancyConfig, resolvePoolerBleedConfig, resolveDefaultPrivilegesConfig, resolveCrossTenantFkConfig, resolveCreateGrantsConfig } from './config.mjs';

// The static guards: synchronous, zero-dependency, no database. These are what
// `tenant-guard run` executes and what a project's vitest/jest suite imports.
export const GUARDS = [migrationCollisions, definerGrants, routeOrgScoping, updatableViews];

export { migrationCollisions, definerGrants, routeOrgScoping, rlsProof, rlsDrift, anonWrites, anonReads, viewIsolation, identityTrust, storageIsolation, constraintOracles, realtimeIsolation, definerRpc, shadowTables, roleCapabilities, schemaTenancy, poolerBleed, defaultPrivileges, crossTenantFk, createGrants, updatableViews };
export { prove } from './guards/rls-proof.mjs';
export { drift } from './guards/rls-drift.mjs';
export { check as checkAnonWrites } from './guards/anon-writes.mjs';
export { check as checkAnonReads } from './guards/anon-reads.mjs';
export { check as checkViews } from './guards/view-isolation.mjs';
export { check as checkIdentity } from './guards/identity-trust.mjs';
export { check as checkStorage } from './guards/storage-isolation.mjs';
export { check as checkOracles } from './guards/constraint-oracles.mjs';
export { check as checkRealtime } from './guards/realtime-isolation.mjs';
export { check as checkDefinerRpc } from './guards/definer-rpc.mjs';
export { check as checkShadowTables } from './guards/shadow-tables.mjs';
export { check as checkCapabilities } from './guards/role-capabilities.mjs';
export { check as checkSchemaTenancy } from './guards/schema-tenancy.mjs';
export { check as checkPoolerBleed } from './guards/pooler-bleed.mjs';
export { check as checkDefaultPrivileges } from './guards/default-privileges.mjs';
export { check as checkCrossTenantFk } from './guards/cross-tenant-fk.mjs';
export { check as checkCreateGrants } from './guards/create-grants.mjs';
// Output serialisers — so a programmatic caller gets the same JSON/SARIF the
// CLI emits instead of re-deriving the shape. Documented in docs/OUTPUT.md.
export { toJson, toJsonString, summarise, statusOf, SCHEMA_VERSION } from './output/json.mjs';
export { toSarif, toSarifString } from './output/sarif.mjs';
export { toMarkdown } from './output/markdown.mjs';
export { VERSION } from './version.mjs';

export { loadConfig, resolveGuardConfigs, resolveProveConfig, resolveDriftConfig, resolveAnonWritesConfig, resolveAnonReadsConfig, resolveViewIsolationConfig, resolveIdentityTrustConfig, resolveStorageConfig, resolveOraclesConfig, resolveRealtimeConfig, resolveDefinerRpcConfig, resolveShadowConfig, resolveCapabilitiesConfig, resolveSchemaTenancyConfig } from './config.mjs';

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

/**
 * Run the constraint-oracle check (async; needs a database URL + `pg`). RLS hides
 * rows but not constraints, and constraints are enforced below it — a globally
 * UNIQUE natural key lets anyone test whether a value exists in another tenant.
 * Catalog-only: no probing, no transaction.
 */
export async function runOracles(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return constraintOracles.run(resolveOraclesConfig(config));
}

/**
 * Run the Supabase Realtime isolation check (async; needs a database URL + `pg`).
 * Broadcast/Presence authorize channels through RLS on `realtime.messages`, and
 * the tenant lives in the TOPIC rather than a column. Skips cleanly without it.
 */
export async function runRealtime(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return realtimeIsolation.run(resolveRealtimeConfig(config));
}

/**
 * Run EVERY guard: the static ones, then each runtime guard in turn. The
 * one-command answer to "check everything" now that there are a dozen of them.
 * Runtime guards with no database simply skip — and a skip is never a pass.
 */
export async function runEverything(cwd = process.cwd()) {
  const results = runAll(cwd);
  for (const fn of [runProof, runDrift, runAnonReads, runAnonWrites, runViews, runIdentity, runDefinerRpc, runShadowTables, runCapabilities, runSchemaTenancy, runPoolerBleed, runDefaultPrivileges, runCrossTenantFk, runCreateGrants, runStorage, runOracles, runRealtime]) {
    results.push(await fn(cwd));
  }
  return results;
}

/**
 * Run the SECURITY DEFINER RPC check (async; needs a database URL + `pg`). A
 * definer function runs as its owner and bypasses RLS, so one that doesn't
 * re-filter by tenant — or trusts a tenant argument — routes around perfectly
 * good policies. Only STABLE/IMMUTABLE functions are ever called: Postgres
 * guarantees those cannot write.
 */
export async function runDefinerRpc(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return definerRpc.run(resolveDefinerRpcConfig(config));
}

/**
 * Run the shadow-table check (async; needs a database URL + `pg`). Follows
 * triggers on tenant tables to the tables they write into, and flags any
 * destination the app role can read that has no RLS — where tenant data lands
 * and nothing follows it.
 */
export async function runShadowTables(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return shadowTables.run(resolveShadowConfig(config));
}

/**
 * Run the role-capability check (async; needs a database URL + `pg`). Catalog
 * only: which RLS-bypassing capabilities (dblink, file reads) and auth-schema
 * grants the app role holds. Outbound-HTTP capability is surfaced as a note.
 */
export async function runCapabilities(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return roleCapabilities.run(resolveCapabilitiesConfig(config));
}

/**
 * Run the schema-per-tenant check (async; needs a database URL + `pg`). Proves
 * how many tenant schemas one role can actually READ — in that architecture the
 * boundary is GRANTs and nothing else. Skips cleanly on a column-tenancy database.
 */
export async function runSchemaTenancy(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return schemaTenancy.run(resolveSchemaTenancyConfig(config));
}

/**
 * Run the pooler-bleed check (async; needs a database URL + `pg`). The only
 * guard that reads BOTH the catalog and your source: the database says which
 * custom GUCs your policies authorize from, the source says whether you set
 * them for the connection instead of the transaction. Skips cleanly when no
 * policy uses a custom GUC.
 */
export async function runPoolerBleed(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return poolerBleed.run(resolvePoolerBleedConfig(config), cwd);
}

/**
 * Run the default-privileges check (async; needs a database URL + `pg`). The
 * only guard about the database as it WILL be: it creates a table inside a
 * rolled-back transaction and reports what that table actually inherited,
 * because ALTER DEFAULT PRIVILEGES makes every other green run conditional.
 */
export async function runDefaultPrivileges(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return defaultPrivileges.run(resolveDefaultPrivilegesConfig(config));
}

/**
 * Run the cross-tenant foreign-key check (async; needs a database URL + `pg`).
 * Referential integrity checks always bypass RLS, so an FK carrying an id but
 * not the tenant lets one tenant point at another's row — and ON DELETE CASCADE
 * turns that into one tenant DELETING another tenant's data.
 */
export async function runCrossTenantFk(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return crossTenantFk.run(resolveCrossTenantFkConfig(config));
}

/**
 * Run the CREATE-grant check (async; needs a database URL + `pg`). Catalog-only.
 * CREATE is the precondition for shadowing an object that a SECURITY DEFINER
 * function then runs as its owner — reported even when no such function exists
 * yet, since the grant arms the next one.
 */
export async function runCreateGrants(cwd = process.cwd()) {
  const config = loadConfig(cwd);
  return createGrants.run(resolveCreateGrantsConfig(config));
}
