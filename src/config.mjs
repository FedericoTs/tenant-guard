/**
 * Config loading + autodetection. Zero dependencies.
 *
 * tenant-guard reads `tenant-guard.config.json` from the working directory.
 * Every guard is opt-in per project via that file; a guard with no config (and
 * whose paths don't autodetect) SKIPS rather than fails — the tool never
 * punishes you for a stack it doesn't apply to.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export const CONFIG_FILENAME = 'tenant-guard.config.json';

const CANDIDATE_MIGRATION_DIRS = [
  'supabase/migrations',
  'migrations',
  'db/migrations',
  'drizzle',
  'prisma/migrations',
];

const CANDIDATE_ROUTE_DIRS = ['src/app/api', 'app/api', 'src/pages/api', 'pages/api'];

function firstExisting(cwd, candidates) {
  for (const c of candidates) if (existsSync(join(cwd, c))) return c;
  return null;
}

/** Load config from disk if present, else empty. */
export function loadConfig(cwd = process.cwd()) {
  const path = join(cwd, CONFIG_FILENAME);
  if (!existsSync(path)) return { cwd, __present: false };
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return { ...parsed, cwd, __present: true };
  } catch (e) {
    throw new Error(`Failed to parse ${CONFIG_FILENAME}: ${e.message}`);
  }
}

/**
 * Resolve the per-guard config, autodetecting paths where the user left them
 * blank. Absolute migration dirs are produced for the filesystem guards.
 */
export function resolveGuardConfigs(config) {
  const cwd = config.cwd ?? process.cwd();
  const migrationsRel =
    config.migrations?.dir ?? firstExisting(cwd, CANDIDATE_MIGRATION_DIRS) ?? null;
  const migrationsDir = migrationsRel ? join(cwd, migrationsRel) : null;
  const routesRel = config.routeOrgScoping?.routesDir ?? firstExisting(cwd, CANDIDATE_ROUTE_DIRS);

  return {
    'migration-collisions': {
      dir: migrationsDir,
      grandfather: config.migrations?.grandfather ?? [],
    },
    'definer-grants': {
      dir: migrationsDir,
      baseline: config.definerGrants?.baseline ?? 0,
      allowlist: config.definerGrants?.allowlist ?? [],
    },
    'route-org-scoping': {
      cwd,
      routesDir: routesRel ?? undefined,
      routeFilePattern: config.routeOrgScoping?.routeFilePattern,
      authSignals: config.routeOrgScoping?.authSignals,
      idFilterPattern: config.routeOrgScoping?.idFilterPattern,
      tenantSignals: config.routeOrgScoping?.tenantSignals,
      allowlist: config.routeOrgScoping?.allowlist ?? [],
    },
  };
}

/**
 * Resolve the runtime RLS-proof config from the user's `rlsProof` block. Only
 * the keys the user set are returned; the guard fills the rest from its own
 * DEFAULTS. Absent block => {} => guard runs with defaults (and skips unless a
 * database URL is present in the environment).
 */
export function resolveProveConfig(config) {
  const p = config.rlsProof ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'role', 'becomeTenant', 'tables', 'grandfather', 'sampleLimit', 'probeWrites', 'seed']) {
    if (p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/**
 * Resolve the RLS-drift config: the (autodetected) migrations dir plus the
 * user's `rlsDrift` block. Absent block => defaults; the guard skips unless a
 * database URL is present in the environment.
 */
export function resolveDriftConfig(config) {
  const cwd = config.cwd ?? process.cwd();
  const migrationsRel = config.migrations?.dir ?? firstExisting(cwd, CANDIDATE_MIGRATION_DIRS) ?? null;
  const out = { migrationsDir: migrationsRel ? join(cwd, migrationsRel) : null };
  const d = config.rlsDrift ?? {};
  for (const k of ['url', 'urlEnv', 'schemas', 'allowlist']) {
    if (d[k] !== undefined) out[k] = d[k];
  }
  return out;
}

export function autodetect(cwd = process.cwd()) {
  return {
    migrationsDir: firstExisting(cwd, CANDIDATE_MIGRATION_DIRS),
    routesDir: firstExisting(cwd, CANDIDATE_ROUTE_DIRS),
  };
}
