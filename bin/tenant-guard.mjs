#!/usr/bin/env node
/**
 * tenant-guard CLI.
 *
 *   tenant-guard run     run every static guard; exit 1 on any violation
 *   tenant-guard prove   runtime RLS proof against a database; exit 1 on a leak
 *   tenant-guard init    write a tenant-guard.config.json, seeded from this repo
 *   tenant-guard list    list the available guards and what each prevents
 *
 * `run`, `init`, `list` are zero-dependency and run in CI without `npm ci`.
 * `prove` additionally needs a database URL and the `pg` driver; without them it
 * skips (a skip is not a pass — it says so).
 */
import { writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { GUARDS, runAll, runProof } from '../src/index.mjs';
import { rlsProof } from '../src/index.mjs';
import { CONFIG_FILENAME, autodetect } from '../src/config.mjs';
import { report, bold, dim, green, yellow } from '../src/runner.mjs';

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

if (cmd === 'list') {
  console.log(bold('\ntenant-guard guards\n'));
  for (const g of [...GUARDS, rlsProof]) {
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
      // the canonical Postgres pattern. For Supabase JWT policies use e.g.
      // ["select set_config('request.jwt.claims', json_build_object('org_id',$1)::text, true)"]
      becomeTenant: ["select set_config('app.current_tenant', $1, true)"],
      grandfather: [],
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

console.error(`Unknown command: ${cmd}\nUsage: tenant-guard [run|prove|init|list]`);
process.exit(2);
