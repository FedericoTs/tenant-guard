#!/usr/bin/env node
/**
 * tenant-guard CLI.
 *
 *   tenant-guard run     run every static guard; exit 1 on any violation
 *   tenant-guard prove   runtime RLS proof against a database; exit 1 on a leak
 *   tenant-guard drift   compare migrations vs the database's RLS; exit 1 on drift
 *   tenant-guard anon-writes  exit 1 if the anon role can write any table
 *   tenant-guard anon-reads   exit 1 if the anon role can read any tenant table
 *   tenant-guard views   exit 1 if a view/matview leaks across tenants
 *   tenant-guard identity exit 1 if the identity your policies trust is forgeable
 *   tenant-guard storage  exit 1 if Supabase Storage leaks across tenant folders
 *   tenant-guard oracles  exit 1 if a UNIQUE key reveals another tenant’s rows
 *   tenant-guard init    write a tenant-guard.config.json, seeded from this repo
 *   tenant-guard list    list the available guards and what each prevents
 *
 * `run`, `init`, `list` are zero-dependency and run in CI without `npm ci`.
 * `prove`, `drift`, `anon-writes`, `anon-reads`, `views` additionally need a
 * database URL and the `pg` driver; without them they skip (a skip is not a pass
 * — it says so).
 */
import { writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { GUARDS, runAll, runProof, runDrift, runAnonWrites, runAnonReads, runViews, runIdentity, runStorage, runOracles } from '../src/index.mjs';
import { rlsProof, rlsDrift, anonWrites, anonReads, viewIsolation, identityTrust, storageIsolation, constraintOracles } from '../src/index.mjs';
import { CONFIG_FILENAME, autodetect } from '../src/config.mjs';
import { report, bold, dim, green, yellow } from '../src/runner.mjs';

const SKIP_HINT = (c) =>
  '  (A skip is not a pass. Point it at a seeded test/staging database:\n' +
  `   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard ${c})\n`;

const cmd = process.argv[2] ?? 'run';
const cwd = process.cwd();

if (cmd === 'run') {
  const code = report(runAll(cwd));
  process.exit(code);
}

if (cmd === 'prove') {
  // Runtime RLS proof. Async — needs a database. Exit 1 only on a proven leak.
  const result = await runProof(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(
      dim(
        '  (A skip is not a pass. Point it at a seeded test/staging database:\n' +
          `   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard prove)\n`,
      ),
    );
  }
  process.exit(code);
}

if (cmd === 'drift') {
  // Compare migration-declared RLS against the live catalog. Async — needs a DB.
  const result = await runDrift(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(
      dim(
        '  (A skip is not a pass. Point it at a migrated test/staging database:\n' +
          `   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard drift)\n`,
      ),
    );
  }
  process.exit(code);
}

if (cmd === 'anon-writes') {
  // Flag tables the unauthenticated role can write. Async — needs a DB.
  const result = await runAnonWrites(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(dim('  (A skip is not a pass. Point it at a test/staging database:\n   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard anon-writes)\n'));
  }
  process.exit(code);
}

if (cmd === 'anon-reads') {
  // Prove the unauthenticated role cannot read tenant tables. Async — needs a DB.
  const result = await runAnonReads(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(dim('  (A skip is not a pass. Point it at a test/staging database:\n   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard anon-reads)\n'));
  }
  process.exit(code);
}

if (cmd === 'views') {
  // Prove views/matviews don't leak across tenants. Async — needs a DB.
  const result = await runViews(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(dim('  (A skip is not a pass. Point it at a seeded test/staging database:\n   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard views)\n'));
  }
  process.exit(code);
}

if (cmd === 'identity') {
  // Can the caller FORGE the identity the policies authorize from? Async — needs a DB.
  const result = await runIdentity(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(dim('  (A skip is not a pass. Point it at a seeded test/staging database:\n   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard identity)\n'));
  }
  process.exit(code);
}

if (cmd === 'storage') {
  // Supabase Storage: object paths, not columns. Async — needs a DB.
  const result = await runStorage(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(dim('  (A skip is not a pass. Point it at a seeded test/staging database:\n   export TENANT_GUARD_DATABASE_URL=postgres://…  &&  npm i -D pg  &&  tenant-guard storage)\n'));
  }
  process.exit(code);
}

if (cmd === 'oracles') {
  // Constraints enforced below RLS. Catalog-only. Async — needs a DB.
  const result = await runOracles(cwd);
  const code = report([result], { emptyHint: false });
  if (result.skipped) {
    console.log(dim(SKIP_HINT('oracles')));
  }
  process.exit(code);
}

if (cmd === 'list') {
  console.log(bold('\ntenant-guard guards\n'));
  for (const g of [...GUARDS, rlsProof, rlsDrift, anonWrites, anonReads, viewIsolation, identityTrust, storageIsolation, constraintOracles]) {
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

console.error(`Unknown command: ${cmd}\nUsage: tenant-guard [run|prove|drift|anon-writes|anon-reads|views|identity|storage|oracles|init|list]`);
process.exit(2);
