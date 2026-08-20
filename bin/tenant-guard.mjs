#!/usr/bin/env node
/**
 * tenant-guard CLI.
 *
 *   tenant-guard <command> [--json[=file]] [--sarif[=file]] [--quiet]
 *
 * Run `tenant-guard --help` for the full list. Every command exits 0 when it
 * passes and 1 when a guard fails, whatever the output format — the exit code
 * is the contract, the formats are for whoever reads it afterwards.
 *
 * `run`, `init`, `list` are zero-dependency and run in CI without `npm ci`.
 * The runtime commands additionally need a database URL and the `pg` driver;
 * without them they skip (a skip is not a pass — it says so).
 */
import { writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import {
  GUARDS, runAll, runProof, runDrift, runAnonWrites, runAnonReads, runViews, runIdentity,
  runStorage, runOracles, runRealtime, runDefinerRpc, runShadowTables, runCapabilities,
  runSchemaTenancy, runPoolerBleed, runDefaultPrivileges, runCrossTenantFk, runEverything,
} from '../src/index.mjs';
import {
  rlsProof, rlsDrift, anonWrites, anonReads, viewIsolation, identityTrust, storageIsolation,
  constraintOracles, realtimeIsolation, definerRpc, shadowTables, roleCapabilities, schemaTenancy,
  poolerBleed, defaultPrivileges, crossTenantFk,
} from '../src/index.mjs';
import { CONFIG_FILENAME, autodetect, loadConfig } from '../src/config.mjs';
import { report, bold, dim, green, yellow, red } from '../src/runner.mjs';
import { toJsonString, summarise } from '../src/output/json.mjs';
import { toSarifString } from '../src/output/sarif.mjs';
import { toMarkdown } from '../src/output/markdown.mjs';
import { VERSION } from '../src/version.mjs';

const ALL_GUARDS = [
  ...GUARDS, rlsProof, rlsDrift, anonWrites, anonReads, viewIsolation, identityTrust,
  storageIsolation, constraintOracles, realtimeIsolation, definerRpc, shadowTables,
  roleCapabilities, schemaTenancy, poolerBleed, defaultPrivileges, crossTenantFk,
];

/**
 * Every command that needs a database, with the flavour of database it needs.
 * `seeded` = needs two tenants' worth of rows to compare; `migrated` = only
 * needs the schema; `any` = a connection is enough.
 */
const RUNTIME_COMMANDS = {
  prove: { fn: runProof, needs: 'seeded' },
  drift: { fn: runDrift, needs: 'migrated' },
  'anon-writes': { fn: runAnonWrites, needs: 'any' },
  'anon-reads': { fn: runAnonReads, needs: 'any' },
  views: { fn: runViews, needs: 'seeded' },
  identity: { fn: runIdentity, needs: 'seeded' },
  storage: { fn: runStorage, needs: 'seeded' },
  oracles: { fn: runOracles, needs: 'migrated' },
  realtime: { fn: runRealtime, needs: 'seeded' },
  rpc: { fn: runDefinerRpc, needs: 'seeded' },
  shadows: { fn: runShadowTables, needs: 'migrated' },
  caps: { fn: runCapabilities, needs: 'migrated' },
  schemas: { fn: runSchemaTenancy, needs: 'seeded' },
  pooler: { fn: runPoolerBleed, needs: 'migrated' },
  defaults: { fn: runDefaultPrivileges, needs: 'migrated' },
  fks: { fn: runCrossTenantFk, needs: 'seeded' },
  all: { fn: runEverything, needs: 'seeded', many: true },
};

const DB_FLAVOUR = {
  seeded: 'a seeded test/staging database',
  migrated: 'a migrated test/staging database',
  any: 'a test/staging database',
};

const skipHint = (cmd, needs) =>
  '  (A skip is not a pass. Point it at ' + DB_FLAVOUR[needs] + ':\n' +
  `   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard ${cmd})\n`;

// ── argument parsing ─────────────────────────────────────────────────
// One positional (the command) plus long flags. `--flag=value` only — no
// space-separated values, so nothing is ambiguous when a value is omitted.

const argv = process.argv.slice(2);
const flags = { json: null, sarif: null, markdown: null, quiet: false, help: false, version: false };
const positionals = [];

for (const arg of argv) {
  if (!arg.startsWith('-')) { positionals.push(arg); continue; }
  const [name, ...rest] = arg.split('=');
  const value = rest.length > 0 ? rest.join('=') : null;
  switch (name) {
    case '--json': flags.json = value ?? 'stdout'; break;
    case '--sarif': flags.sarif = value ?? 'stdout'; break;
    case '--markdown': case '--md': flags.markdown = value ?? 'stdout'; break;
    case '--quiet': case '-q': flags.quiet = true; break;
    case '--help': case '-h': flags.help = true; break;
    case '--version': case '-v': flags.version = true; break;
    case '--no-color': process.env.NO_COLOR = '1'; break;
    default:
      console.error(`Unknown option: ${name}\nRun \`tenant-guard --help\` for the supported flags.`);
      process.exit(2);
  }
}

const cmd = positionals[0] ?? 'run';
const cwd = process.cwd();

if (flags.version) { console.log(VERSION); process.exit(0); }

// Two documents cannot share one stdout.
const toStdout = ['json', 'sarif', 'markdown'].filter((f) => flags[f] === 'stdout');
if (toStdout.length > 1) {
  const names = toStdout.map((f) => `--${f}`);
  const listed = names.length === 2
    ? names.join(' and ')
    : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
  console.error(
    `${listed} cannot ${names.length === 2 ? 'both' : 'all'} write to stdout.\n` +
    'Give all but one a file, e.g. --sarif=tenant-guard.sarif',
  );
  process.exit(2);
}

// Anything written to stdout as data means the human report has to get out of
// the way, or the "JSON" a script reads starts with a banner.
const quiet = flags.quiet || toStdout.length > 0;

// ── help ─────────────────────────────────────────────────────────────

const HELP = `
${bold('tenant-guard')} ${dim('— guard tests that fail CI when multi-tenant code can leak across tenants')}

${bold('USAGE')}
  tenant-guard <command> [options]

${bold('COMMANDS')}
  ${bold('run')}            every static guard — no database, no npm ci ${dim('(default)')}
  ${bold('all')}            everything: the static guards plus every runtime proof

  ${dim('Static (files on disk):')}
  init           write a tenant-guard.config.json, seeded from this repo
  list           describe every guard and what it prevents

  ${dim('Runtime (needs TENANT_GUARD_DATABASE_URL + the pg driver):')}
  prove          one tenant cannot read OR write another's rows
  drift          RLS in the database that no migration declares
  anon-reads     the anonymous role can read tenant data
  anon-writes    the anonymous role can write
  identity       the identity your policies trust can be forged
  rpc            a SECURITY DEFINER function routes around RLS
  views          a view or materialized view leaks across tenants
  storage        Supabase Storage paths leak across tenant folders
  realtime       Realtime channels leak across tenants
  schemas        one role reaches more than one tenant SCHEMA
  pooler         a tenant identity outlives the request that set it
  defaults       what a table created TOMORROW will inherit
  fks            a foreign key lets one tenant reach another's rows
  shadows        a trigger copies tenant data somewhere unprotected
  oracles        a UNIQUE key reveals another tenant's rows
  caps           the app role holds an RLS-bypassing capability

${bold('OPTIONS')}
  --json[=FILE]    machine-readable results ${dim('(stdout if FILE is omitted)')}
  --sarif[=FILE]   SARIF 2.1.0 for GitHub code scanning ${dim('(stdout if FILE is omitted)')}
  --markdown[=FILE] a job summary ${dim('(appends; use --markdown=$GITHUB_STEP_SUMMARY)')}
  -q, --quiet      suppress the human-readable report
  --no-color       disable ANSI colour ${dim('(NO_COLOR is also honoured)')}
  -h, --help       this text
  -v, --version    print the version

${bold('EXIT CODES')}
  0  every guard that ran passed        ${dim('(a skip is not a pass)')}
  1  at least one guard failed
  2  bad usage — unknown command or option

  ${dim('The exit code is identical in every output format.')}

${bold('EXAMPLES')}
  npx tenant-guard init                        ${dim('# detect paths, write a config')}
  npx tenant-guard run                         ${dim('# static guards, zero dependencies')}
  npx tenant-guard all --sarif=tg.sarif        ${dim('# everything + upload-ready SARIF')}
  npx tenant-guard all --json | jq .summary    ${dim('# pipe the results anywhere')}
  npx tenant-guard all --markdown=\$GITHUB_STEP_SUMMARY  ${dim('# render on the run page')}

${dim('Docs: https://github.com/FedericoTs/tenant-guard')}
${dim('Output formats: https://github.com/FedericoTs/tenant-guard/blob/main/docs/OUTPUT.md')}
`;

if (flags.help || cmd === 'help') { console.log(HELP); process.exit(0); }

// ── output ───────────────────────────────────────────────────────────

/** Resolve the SARIF file-anchoring context from the repo's own config. */
function sarifContext() {
  let migrationsDir;
  try {
    migrationsDir = loadConfig(cwd)?.migrations?.dir;
  } catch {
    /* a broken config must not stop the report being written */
  }
  return {
    cwd,
    migrationsDir: migrationsDir ?? autodetect(cwd).migrationsDir ?? 'supabase/migrations',
    anchorCandidates: [CONFIG_FILENAME, 'package.json'],
    metaById: new Map(ALL_GUARDS.map((g) => [g.meta.id, g.meta])),
  };
}

function writeOut(target, body, label, { append = false } = {}) {
  if (target === 'stdout') { process.stdout.write(body); return; }
  // resolve, not join: CI runners hand out absolute scratch paths
  // ($RUNNER_TEMP/tg.sarif), and join would glue them onto the cwd.
  const path = resolve(cwd, target);
  mkdirSync(dirname(path), { recursive: true });
  // Markdown appends, because its destination is usually $GITHUB_STEP_SUMMARY —
  // a shared file that other steps also write to. Data formats overwrite.
  if (append) appendFileSync(path, body);
  else writeFileSync(path, body);
  if (!quiet) console.log(dim(`  → wrote ${label} to ${target}`));
}

/**
 * The single exit path for every command that produces results: emit whichever
 * formats were asked for, then return the exit code.
 *
 * The code comes from `summarise`, not from `report`, so that suppressing the
 * human output cannot change the verdict.
 */
function emit(results, { command, hint }) {
  if (!quiet) report(results, { emptyHint: command === 'run' });
  if (flags.json) writeOut(flags.json, toJsonString(results, { command }), 'JSON');
  if (flags.sarif) writeOut(flags.sarif, toSarifString(results, { command, ...sarifContext() }), 'SARIF');
  if (flags.markdown) writeOut(flags.markdown, toMarkdown(results, { command }), 'summary', { append: true });
  if (!quiet && hint && results.some((r) => r.skipped)) console.log(dim(hint));
  return summarise(results).exitCode;
}

// ── commands ─────────────────────────────────────────────────────────

if (cmd === 'run') {
  process.exit(emit(runAll(cwd), { command: 'run' }));
}

if (RUNTIME_COMMANDS[cmd]) {
  const { fn, needs, many } = RUNTIME_COMMANDS[cmd];
  const out = await fn(cwd);
  const results = many ? out : [out];
  process.exit(emit(results, { command: cmd, hint: skipHint(cmd, needs) }));
}

if (cmd === 'list') {
  if (flags.json) {
    // The guard catalogue as data — enough to generate a docs table from.
    const body = JSON.stringify(
      { tool: { name: 'tenant-guard', version: VERSION }, guards: ALL_GUARDS.map((g) => ({ ...g.meta })) },
      null, 2,
    ) + '\n';
    writeOut(flags.json, body, 'JSON');
    process.exit(0);
  }
  console.log(bold('\ntenant-guard guards\n'));
  for (const g of ALL_GUARDS) {
    console.log(`  ${bold(g.meta.id)}`);
    console.log(dim(`    ${g.meta.title}`));
    console.log(dim(`    ${g.meta.why}\n`));
  }
  process.exit(0);
}

if (cmd === 'init') {
  const path = join(cwd, CONFIG_FILENAME);
  if (existsSync(path)) {
    console.log(yellow(`${CONFIG_FILENAME} already exists — not overwriting.`));
    process.exit(0);
  }
  const detected = autodetect(cwd);
  const config = {
    $schema: 'https://github.com/FedericoTs/tenant-guard/blob/main/examples/tenant-guard.config.json',
    migrations: {
      dir: detected.migrationsDir ?? 'supabase/migrations',
      grandfather: [],
    },
    definerGrants: {
      baseline: 0,
      allowlist: [],
    },
    routeOrgScoping: {
      routesDir: detected.routesDir ?? 'src/app/api',
      allowlist: [],
    },
    rlsProof: {
      // The runtime proof runs only when a database URL is present in the
      // environment (below), so it stays skipped until you opt in.
      urlEnv: 'TENANT_GUARD_DATABASE_URL',
      role: 'authenticated',
      // How a session assumes a tenant's identity ($1 = tenant id). Default =
      // the canonical Postgres pattern. For Supabase JWT policies, the shortcut
      // `claim: "org_id"` (or "team_id"/"account_id") builds the request.jwt.claims
      // becomeTenant for you and sets role=authenticated — no JWT secret in CI.
      // Or spell it out (note the $1::text cast — json_build_object can't infer
      // the placeholder type):
      // ["select set_config('request.jwt.claims', json_build_object('org_id', $1::text)::text, true)"]
      becomeTenant: ["select set_config('app.current_tenant', $1, true)"],
      grandfather: [],
    },
    rlsDrift: {
      // Compares migration-declared RLS against the live catalog (same DB URL as
      // rlsProof). Flags policies / RLS that exist in the database but no
      // migration declares — hand-edits that never got committed.
      schemas: ['public'],
      allowlist: [], // "schema.table" or "schema.table::policy_name" managed outside migrations
    },
    anonWrites: {
      // Flags tables the unauthenticated role can INSERT/UPDATE/DELETE (same DB
      // URL as rlsProof). The cache-poisoning class the tenant guards miss.
      role: 'anon',
      schemas: ['public'],
      allowlist: [], // "schema.table" that intentionally accepts anon writes (a public form, etc.)
    },
    anonReads: {
      // Proves the unauthenticated role cannot SELECT tenant tables (same DB URL
      // as rlsProof) — the CVE-2025-48757 class. Scoped to tables with a tenant
      // column, so public content isn't flagged.
      role: 'anon',
      schemas: ['public'],
      allowlist: [], // "schema.table" intentionally readable by anon (published/reference data)
    },
    schemaTenancy: {
      // The OTHER multi-tenant architecture: one schema per tenant, where the
      // boundary is GRANTs and nothing else (search_path is not a control —
      // anyone can write tenant_b.docs directly). Tenant schemas are inferred
      // from shape; set schemaPattern for an irregular layout. Skips cleanly on
      // a column-tenancy database.
      //"schemaPattern": "^tenant_",
      allowlist: [], // schema names shared on purpose
    },
    crossTenantFk: {
      // Foreign keys that reach across tenants. Referential-integrity checks
      // ALWAYS bypass RLS, so an FK carrying an id but not the tenant lets one
      // tenant point their row at another tenant's — and ON DELETE CASCADE turns
      // that into one tenant DELETING another tenant's data. Identity is
      // inherited from rlsProof. Skips when every FK already carries the tenant.
      schemas: ['public'],
      allowlist: [], // "schema.table::constraint_name" that spans tenants on purpose
    },
    defaultPrivileges: {
      // What a table created TOMORROW will inherit. ALTER DEFAULT PRIVILEGES
      // grants on every table created after it, and Postgres never enables RLS
      // by default — so this run being green says nothing about the next table
      // somebody adds. Proves it by creating one inside a rolled-back
      // transaction and reading what it actually inherited.
      schemas: ['public'],
      failRoles: ['PUBLIC'], // add 'anon' to fail the build on it too
      allowlist: [], // schema names that inherit grants on purpose
    },
    poolerBleed: {
      // The tenant identity outliving the request that set it. Reads BOTH the
      // catalog (which custom GUCs your policies authorize from) and your
      // SOURCE (whether you set them for the connection instead of the
      // transaction). set_config(guc, v, false) and a bare SET last for the
      // whole connection, so the next request on a pooled connection inherits
      // the previous tenant. Skips cleanly when no policy uses a custom GUC.
      schemas: ['public'],
      sourceDirs: ['src', 'app', 'lib', 'server', 'api', 'db'],
      allowlist: [], // GUC names that are session-scoped on purpose
    },
    shadowTables: {
      // Follows triggers on tenant tables to the tables they WRITE into. An audit
      // log or outbox with no tenant column and no RLS holds every tenant's
      // activity, and the tenant-column guards walk past it.
      schemas: ['public'],
      allowlist: [], // "schema.table" destinations that are unscoped on purpose
    },
    roleCapabilities: {
      // Catalog-only. Capabilities that defeat RLS outright (dblink opens a new
      // connection as another role; file reads never touch the policy layer) and
      // direct grants on the auth schema. Outbound HTTP is surfaced as a note.
      allowlist: [], // "schema.function" or "auth.table" granted on purpose
    },
    definerRpc: {
      // A SECURITY DEFINER function runs as its OWNER and bypasses RLS, and
      // PostgREST exposes it at /rest/v1/rpc/<name>. Only STABLE/IMMUTABLE
      // functions are ever CALLED — Postgres guarantees those cannot write.
      schemas: ['public'],
      allowlist: [], // "schema.function" that is intentionally cross-tenant (an admin RPC)
    },
    realtimeIsolation: {
      // Broadcast/Presence authorize channels through RLS on realtime.messages,
      // and the tenant lives in the TOPIC (org_A:notifications), not a column.
      // Skips cleanly if there is no realtime schema.
      topicSeparator: ':',
      allowlist: [], // topic prefixes that are intentionally global (a status channel)
    },
    constraintOracles: {
      // RLS hides rows, not constraints — and constraints are enforced below it.
      // A globally UNIQUE natural key on a tenant table lets anyone test whether
      // a value exists in another tenant. Catalog-only; no probing.
      schemas: ['public'],
      allowlist: [], // "schema.table" / "schema.index" that is intentionally global (a public slug)
    },
    storageIsolation: {
      // Supabase Storage keys tenancy off the object PATH (org_A/file.pdf), not a
      // column — and the client chooses that path on upload. Skips cleanly if
      // there is no storage schema. Identity is inherited from rlsProof.
      pathSegment: 1, // which '/'-separated segment identifies the tenant
      allowlist: [], // bucket ids that are genuinely public (logos, marketing assets)
    },
    identityTrust: {
      // Asks whether the caller can FORGE the identity your policies authorize
      // from: user-writable JWT claims (user_metadata), or a callable SECURITY
      // DEFINER function that sets the tenant GUC from an argument. Identity
      // config is inherited from rlsProof unless set here.
      schemas: ['public'],
      allowlist: [], // "schema.policyname" / "schema.table" / "schema.function"
    },
    viewIsolation: {
      // Proves VIEWS and MATERIALIZED VIEWS don't leak across tenants. A view
      // runs with its OWNER's rights unless security_invoker is set, and RLS
      // never applies to a materialized view at all — so a perfectly-RLS'd table
      // can still be handed out wholesale by the view beside it. Identity
      // (role/becomeTenant/claim) is inherited from rlsProof unless set here.
      schemas: ['public'],
      allowlist: [], // "schema.view" that intentionally spans tenants (an admin reporting view)
    },
  };
  writeFileSync(path, JSON.stringify(config, null, 2) + '\n');
  console.log(green(`✓ wrote ${CONFIG_FILENAME}`));
  console.log(
    dim(
      `  detected migrations: ${detected.migrationsDir ?? '(none — set migrations.dir)'}\n` +
        `  detected routes:     ${detected.routesDir ?? '(none — set routeOrgScoping.routesDir)'}\n\n` +
        `  Next: run \`tenant-guard run\`. If it flags legacy code you can't fix yet,\n` +
        `  add those exact files/numbers to the matching allowlist so the guard goes green —\n` +
        `  now it can only get better. Wire \`tenant-guard run\` into CI.`,
    ),
  );
  process.exit(0);
}

console.error(red(`Unknown command: ${cmd}`) + '\nRun `tenant-guard --help` for the full list.');
process.exit(2);
