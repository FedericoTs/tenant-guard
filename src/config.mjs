/**
 * Config loading + autodetection. Zero dependencies.
 *
 * tenant-guard reads `tenant-guard.config.json` from the working directory.
 * Every guard is opt-in per project via that file; a guard with no config (and
 * whose paths don't autodetect) SKIPS rather than fails — the tool never
 * punishes you for a stack it doesn't apply to.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
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
/**
 * Drop keys whose value is `undefined`.
 *
 * `{ ...DEFAULTS, ...config }` treats an explicitly-undefined key as a value and
 * overwrites the default with it, so a resolver that returns
 * `option: config.block?.option` silently erases the default whenever the user
 * did not set that option. Stripping them keeps the spread meaning what it reads
 * like.
 */
export function definedOnly(obj) {
  return Object.fromEntries(Object.entries(obj ?? {}).filter(([, v]) => v !== undefined));
}

/** The tenancy model for this run, detected once from the migrations. */
function detectedTenancy(config) {
  const cwd = config.cwd ?? process.cwd();
  const rel = config.migrations?.dir ?? firstExisting(cwd, CANDIDATE_MIGRATION_DIRS);
  return detectTenancyModel(readMigrationsSql(rel ? join(cwd, rel) : null));
}

export function resolveGuardConfigs(config) {
  const cwd = config.cwd ?? process.cwd();
  const migrationsRel =
    config.migrations?.dir ?? firstExisting(cwd, CANDIDATE_MIGRATION_DIRS) ?? null;
  const migrationsDir = migrationsRel ? join(cwd, migrationsRel) : null;
  const routesRel = config.routeOrgScoping?.routesDir ?? firstExisting(cwd, CANDIDATE_ROUTE_DIRS);

  return definedOnlyDeep({
    'migration-collisions': {
      dir: migrationsDir,
      grandfather: config.migrations?.grandfather ?? [],
    },
    'definer-grants': {
      dir: migrationsDir,
      baseline: config.definerGrants?.baseline ?? 0,
      allowlist: config.definerGrants?.allowlist ?? [],
    },
    'updatable-view-writethrough': {
      dir: migrationsDir,
      exposedRoles: config.updatableViews?.exposedRoles,
      assumeDefaultWriteGrants: config.updatableViews?.assumeDefaultWriteGrants,
      allowlist: config.updatableViews?.allowlist ?? [],
    },
    'route-org-scoping': {
      cwd,
      routesDir: routesRel ?? undefined,
      routeFilePattern: config.routeOrgScoping?.routeFilePattern,
      authSignals: config.routeOrgScoping?.authSignals,
      idFilterPattern: config.routeOrgScoping?.idFilterPattern,
      // Per-USER apps are a large share of the Supabase population, and
      // org-only signals give them a wall of false positives on first run. The
      // model is read from the schema; an explicit config always wins.
      tenantSignals: config.routeOrgScoping?.tenantSignals ?? signalsForModel(detectedTenancy(config).model),
      // How a session-derived filter VALUE is spelled, and which calls are
      // projections rather than filters. These are how the guard tells
      // `.eq('user_id', user.id)` from `.eq('user_id', params.userId)`, so an
      // app that spells its session value differently has to be able to say so.
      sessionValueSignals: config.routeOrgScoping?.sessionValueSignals,
      projectionCalls: config.routeOrgScoping?.projectionCalls,
      allowlist: config.routeOrgScoping?.allowlist ?? [],
    },
  });
}

/** `definedOnly` applied to each guard's block. */
function definedOnlyDeep(byGuard) {
  return Object.fromEntries(Object.entries(byGuard).map(([k, v]) => [k, definedOnly(v)]));
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
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'role', 'becomeTenant', 'claim', 'tables', 'grandfather', 'sampleLimit', 'probeWrites', 'seed']) {
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

/** Resolve the anon-write-surface config from the user's `anonWrites` block. */
export function resolveAnonWritesConfig(config) {
  const a = config.anonWrites ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'role', 'allowlist']) {
    if (a[k] !== undefined) out[k] = a[k];
  }
  return out;
}

/** Resolve the anon-read-surface config from the user's `anonReads` block. */
export function resolveAnonReadsConfig(config) {
  const a = config.anonReads ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'role', 'grandfather', 'allowlist']) {
    if (a[k] !== undefined) out[k] = a[k];
  }
  return out;
}

/** Resolve the view-isolation config from the user's `viewIsolation` block. */
export function resolveViewIsolationConfig(config) {
  const v = config.viewIsolation ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'role', 'becomeTenant', 'claim', 'allowlist', 'sampleLimit']) {
    if (v[k] !== undefined) out[k] = v[k];
  }
  // Views are probed with the same identity as the RLS proof; inherit it unless
  // the user configured viewIsolation explicitly, so `claim`/`becomeTenant` only
  // have to be written once.
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'becomeTenant', 'claim', 'tenantColumns', 'schemas']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the identity-trust config from the user's `identityTrust` block. */
export function resolveIdentityTrustConfig(config) {
  const i = config.identityTrust ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'authorizationColumns', 'role', 'becomeTenant', 'claim', 'allowlist']) {
    if (i[k] !== undefined) out[k] = i[k];
  }
  // Identity is inherited from rlsProof so it is configured once.
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'becomeTenant', 'claim', 'tenantColumns', 'schemas']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the storage-isolation config from the user's `storageIsolation` block. */
export function resolveStorageConfig(config) {
  const s = config.storageIsolation ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'becomeTenant', 'claim', 'pathSegment', 'buckets', 'allowlist', 'sampleLimit', 'probeWrites']) {
    if (s[k] !== undefined) out[k] = s[k];
  }
  // Identity is inherited from rlsProof so it is configured once.
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'becomeTenant', 'claim']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the constraint-oracles config from the user's `constraintOracles` block. */
export function resolveOraclesConfig(config) {
  const o = config.constraintOracles ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'allowlist', 'unguessableTypes']) {
    if (o[k] !== undefined) out[k] = o[k];
  }
  const p = config.rlsProof ?? {};
  for (const k of ['tenantColumns', 'schemas']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the realtime-isolation config from the user's `realtimeIsolation` block. */
export function resolveRealtimeConfig(config) {
  const r = config.realtimeIsolation ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'becomeTenant', 'claim', 'tenantColumns', 'topicSeparator', 'allowlist', 'sampleLimit', 'probeWrites']) {
    if (r[k] !== undefined) out[k] = r[k];
  }
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'becomeTenant', 'claim', 'tenantColumns']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the definer-rpc config from the user's `definerRpc` block. */
export function resolveDefinerRpcConfig(config) {
  const d = config.definerRpc ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'role', 'becomeTenant', 'claim', 'allowlist', 'tenantArgTypes']) {
    if (d[k] !== undefined) out[k] = d[k];
  }
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'becomeTenant', 'claim', 'tenantColumns', 'schemas']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the shadow-tables config from the user's `shadowTables` block. */
export function resolveShadowConfig(config) {
  const s = config.shadowTables ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'schemas', 'tenantColumns', 'role', 'allowlist']) {
    if (s[k] !== undefined) out[k] = s[k];
  }
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'tenantColumns', 'schemas']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the role-capabilities config from the user's `roleCapabilities` block. */
export function resolveCapabilitiesConfig(config) {
  const c = config.roleCapabilities ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'allowlist', 'rlsBypassFunctions', 'egressFunctions', 'authTables']) {
    if (c[k] !== undefined) out[k] = c[k];
  }
  const p = config.rlsProof ?? {};
  if (out.role === undefined && p.role !== undefined) out.role = p.role;
  return out;
}

/** Resolve the schema-tenancy config from the user's `schemaTenancy` block. */
export function resolveSchemaTenancyConfig(config) {
  const s = config.schemaTenancy ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'schemaPattern', 'systemSchemas', 'allowlist']) {
    if (s[k] !== undefined) out[k] = s[k];
  }
  const p = config.rlsProof ?? {};
  if (out.role === undefined && p.role !== undefined) out.role = p.role;
  return out;
}

/**
 * Resolve the pooler-bleed config from the user's `poolerBleed` block.
 * Inherits the app role from rlsProof, like the other runtime guards.
 */
export function resolvePoolerBleedConfig(config) {
  const b = config.poolerBleed ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'schemas', 'sourceDirs', 'sourceExtensions', 'skipDirs', 'maxFileBytes', 'allowlist']) {
    if (b[k] !== undefined) out[k] = b[k];
  }
  const p = config.rlsProof ?? {};
  if (out.role === undefined && p.role !== undefined) out.role = p.role;
  return out;
}

/** Resolve the default-privileges config from the user's `defaultPrivileges` block. */
export function resolveDefaultPrivilegesConfig(config) {
  const d = config.defaultPrivileges ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'schemas', 'failRoles', 'unauthenticatedRoles', 'probeTable', 'allowlist']) {
    if (d[k] !== undefined) out[k] = d[k];
  }
  const p = config.rlsProof ?? {};
  if (out.role === undefined && p.role !== undefined) out.role = p.role;
  return out;
}

/** Resolve the cross-tenant-FK config from the user's `crossTenantFk` block. */
export function resolveCrossTenantFkConfig(config) {
  const f = config.crossTenantFk ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'becomeTenant', 'claim', 'schemas', 'tenantColumns', 'allowlist']) {
    if (f[k] !== undefined) out[k] = f[k];
  }
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'becomeTenant', 'claim', 'tenantColumns']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the create-grants config from the user's `createGrants` block. */
export function resolveCreateGrantsConfig(config) {
  const c = config.createGrants ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'schemas', 'unauthenticatedRoles', 'allowlist']) {
    if (c[k] !== undefined) out[k] = c[k];
  }
  const p = config.rlsProof ?? {};
  if (out.role === undefined && p.role !== undefined) out.role = p.role;
  return out;
}

/** Column names that mean "this row belongs to an organisation". */
export const ORG_TENANT_COLUMNS = ['organization_id', 'organisation_id', 'tenant_id', 'account_id', 'workspace_id', 'org_id', 'team_id'];
/** Column names that mean "this row belongs to a person". */
export const USER_TENANT_COLUMNS = ['user_id', 'owner_id', 'created_by', 'profile_id', 'author_id'];

/** Route-file signals for each model, matching how the columns are written in TS. */
export const ORG_TENANT_SIGNALS = ['organization_id', 'organizationId', 'tenant_id', 'tenantId', 'org_id', 'account_id', 'workspace_id'];
export const USER_TENANT_SIGNALS = ['user_id', 'userId', 'user.id', 'owner_id', 'ownerId', 'auth.uid', 'created_by', 'createdBy'];

/**
 * Which tenancy model is this schema built on?
 *
 * A large share of the apps this tool targets — anything built on Supabase Auth,
 * which is most of the "vibe-coded" population — are per-USER multi-tenant: the
 * tenant is `auth.uid()` and there is no organisation at all. Defaulting to
 * org-only columns hands those projects a wall of false positives on their first
 * run, which is the fastest way to be uninstalled.
 *
 * Decided by counting column declarations in the migrations, so it reflects the
 * schema rather than a guess about the framework.
 *
 * @returns {{model:'org'|'user'|'both'|'unknown', org:number, user:number}}
 */
export function detectTenancyModel(migrationsSql) {
  const sql = String(migrationsSql ?? '').toLowerCase();
  const count = (names) => names.reduce(
    (n, col) => n + (sql.match(new RegExp(`\\b${col}\\b`, 'g')) ?? []).length,
    0,
  );
  const org = count(ORG_TENANT_COLUMNS);
  const user = count(USER_TENANT_COLUMNS);

  if (org === 0 && user === 0) return { model: 'unknown', org, user };
  if (org === 0) return { model: 'user', org, user };
  if (user === 0) return { model: 'org', org, user };
  // Both present: an org app that also stamps a creator is still org-tenanted,
  // so only call it user-tenanted when the user columns clearly dominate.
  if (user >= org * 3) return { model: 'user', org, user };
  if (org >= user * 3) return { model: 'org', org, user };
  return { model: 'both', org, user };
}

/** The tenant signals implied by a detected model. */
export function signalsForModel(model) {
  if (model === 'user') return [...USER_TENANT_SIGNALS];
  if (model === 'both') return [...ORG_TENANT_SIGNALS, ...USER_TENANT_SIGNALS];
  return [...ORG_TENANT_SIGNALS];
}

/** The tenant COLUMNS implied by a detected model, for the runtime guards. */
export function tenantColumnsForModel(model) {
  if (model === 'user') return [...USER_TENANT_COLUMNS];
  if (model === 'both') return [...ORG_TENANT_COLUMNS, ...USER_TENANT_COLUMNS];
  return [...ORG_TENANT_COLUMNS];
}

/** Read every migration as one string, for detection. Empty when there are none. */
export function readMigrationsSql(dir) {
  if (!dir || !existsSync(dir)) return '';
  try {
    return readdirSync(dir)
      .filter((f) => f.endsWith('.sql'))
      .map((f) => readFileSync(join(dir, f), 'utf8'))
      .join('\n');
  } catch {
    return '';
  }
}

/**
 * Resolve the column-exposure config from the user's `columnExposure` block.
 *
 * The role defaults to `anon` and is inherited from `anonReads`, not `rlsProof`
 * — this guard asks what an UNAUTHENTICATED visitor reads, so the authenticated
 * role would be the wrong question entirely.
 */
export function resolveColumnExposureConfig(config) {
  const m = config.columnExposure ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'schemas', 'tenantColumns', 'sampleRows', 'allowlist']) {
    if (m[k] !== undefined) out[k] = m[k];
  }
  const a = config.anonReads ?? {};
  for (const k of ['role', 'schemas']) {
    if (out[k] === undefined && a[k] !== undefined) out[k] = a[k];
  }
  const p = config.rlsProof ?? {};
  if (out.schemas === undefined && p.schemas !== undefined) out.schemas = p.schemas;
  // Tenant columns are used ONLY to hand a relation off to anon-reads, so they
  // follow the same detected model as every other guard.
  if (out.tenantColumns === undefined) {
    out.tenantColumns = p.tenantColumns ?? tenantColumnsForModel(detectedTenancy(config).model);
  }
  return out;
}

/** Resolve the trigger-visibility config from the user's `triggerVisibility` block. */
export function resolveTriggerVisibilityConfig(config) {
  const m = config.triggerVisibility ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'schemas', 'allowlist']) {
    if (m[k] !== undefined) out[k] = m[k];
  }
  // The role is the one whose writes fire the trigger, so it follows rlsProof's
  // app role rather than the anonymous one.
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'schemas']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  return out;
}

/** Resolve the MFA-enforcement config from the user's `mfaEnforcement` block. */
export function resolveMfaEnforcementConfig(config) {
  const m = config.mfaEnforcement ?? {};
  const out = {};
  for (const k of ['url', 'urlEnv', 'role', 'schemas', 'tenantColumns', 'allowlist']) {
    if (m[k] !== undefined) out[k] = m[k];
  }
  const p = config.rlsProof ?? {};
  for (const k of ['role', 'schemas']) {
    if (out[k] === undefined && p[k] !== undefined) out[k] = p[k];
  }
  // Tenant columns follow the detected tenancy model, like everything else.
  if (out.tenantColumns === undefined) {
    out.tenantColumns = p.tenantColumns ?? tenantColumnsForModel(detectedTenancy(config).model);
  }
  return out;
}

export function autodetect(cwd = process.cwd()) {
  const migrationsDir = firstExisting(cwd, CANDIDATE_MIGRATION_DIRS);
  const tenancy = detectTenancyModel(readMigrationsSql(migrationsDir ? join(cwd, migrationsDir) : null));
  return {
    migrationsDir,
    routesDir: firstExisting(cwd, CANDIDATE_ROUTE_DIRS),
    tenancy,
  };
}
