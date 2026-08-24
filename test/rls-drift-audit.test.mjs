/**
 * rls-drift: two ways the guard failed the build on code that was already fully
 * in version control. Both were reproduced against a real catalog (pglite) and
 * a real directory tree before the fix; each test below fails without it.
 *
 * 1. Unquoted identifiers were never case-folded. Postgres lower-cases an
 *    unquoted identifier before storing it; parseDeclaredState did not. So a
 *    migration written as `create policy TenantIsolation on Invoices` declared
 *    `public.Invoices::TenantIsolation` while the catalog held
 *    `public.invoices::tenantisolation` — no match in either direction, which
 *    produced a build-failing "applied out-of-band (dashboard/psql)" violation
 *    AND, in the same run, the contradicting note "migration declares policy
 *    "TenantIsolation" but this database doesn't have it".
 *
 * 2. The migrations directory was read non-recursively, with no warning when
 *    that found nothing. Under Prisma every migration is at
 *    <dir>/<version>/migration.sql — a 100% miss — so the guard diffed the live
 *    catalog against an EMPTY declared set and reported every policy in the
 *    database as unreviewed drift.
 *
 * Why these are the worst kind of bug for this tool: the only two escapes a
 * developer had were to re-declare an already-committed policy (which errors
 * with "policy ... already exists" on the next apply) or to allowlist the
 * table — and allowlisting matches by `schema.table` prefix, so it silences
 * every policy on that table forever, including a genuine dashboard-added one.
 * A guard that fires on correct code teaches people to disable it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  stripQuotes,
  normalizeTable,
  parseDeclaredState,
  collectSqlFiles,
  drift,
  run,
} from '../src/guards/rls-drift.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('rls-drift audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const query = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

// ── 1. identifier case folding ───────────────────────────────────────

test('stripQuotes folds an UNQUOTED identifier and leaves a quoted one exactly alone', () => {
  assert.equal(stripQuotes('Invoices'), 'invoices');
  assert.equal(stripQuotes('TenantIsolation'), 'tenantisolation');
  assert.equal(stripQuotes('"Invoices"'), 'Invoices'); // quoted => case-sensitive, untouched
  assert.equal(stripQuotes('"My Table"'), 'My Table');
});

test('normalizeTable folds unquoted schema and table the way Postgres stores them', () => {
  assert.equal(normalizeTable('Invoices'), 'public.invoices');
  assert.equal(normalizeTable('Billing.Invoices'), 'billing.invoices');
  // still exactly the pre-existing contract for quoted refs
  assert.equal(normalizeTable('"public"."My Table"'), 'public.My Table');
});

test('parse: a mixed-case migration declares the SAME ids the catalog will hold', () => {
  const s = parseDeclaredState([
    {
      name: '001.sql',
      sql: `create table Invoices (id serial primary key, organization_id text);
            alter table Invoices enable row level security;
            create policy TenantIsolation on Invoices using (organization_id = current_setting('app.t', true));`,
    },
  ]);
  assert.ok(s.rlsEnabled.has('public.invoices'), [...s.rlsEnabled].join());
  assert.ok(s.policies.has('public.invoices::tenantisolation'), [...s.policies].join());
});

if (PGlite) {
  // The measured false positive, end to end. Before the fix this returned
  // ok=false with 2 violations and 2 self-contradicting notes.
  test('QUIET on a mixed-case migration applied verbatim — nothing is out-of-band', async () => {
    const sql = `create table Invoices (id serial primary key, organization_id text);
      alter table Invoices enable row level security;
      create policy TenantIsolation on Invoices using (organization_id = current_setting('app.t', true));`;
    const db = new PGlite();
    await db.exec(sql);

    const res = await drift({ query: query(db), files: [{ name: '001_init.sql', sql }] });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.deepEqual(res.violations, []);
    assert.deepEqual(res.notes, [], 'and no contradicting "declares it but the DB lacks it" note either');
  });

  // The folding must not blunt the guard: it touches only the DECLARED side, so
  // a policy that really was added by hand is still caught and named.
  test('still CATCHES a hand-added policy on a mixed-case table', async () => {
    const migration = `create table Invoices (id serial primary key, organization_id text);
      alter table Invoices enable row level security;
      create policy TenantIsolation on Invoices using (organization_id = current_setting('app.t', true));`;
    const db = new PGlite();
    await db.exec(migration);
    await db.exec(`create policy DashboardBackdoor on Invoices for all using (true) with check (true);`);

    const res = await drift({ query: query(db), files: [{ name: '001_init.sql', sql: migration }] });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1);
    assert.match(res.violations[0].message, /dashboardbackdoor.*in NO migration/);
    assert.equal(res.violations[0].where, 'public.invoices');
  });

  // Quoted mixed case is genuinely case-SENSITIVE in Postgres: "Invoices" and
  // invoices are two different tables. Folding must not merge them, or the
  // guard would report clean on a policy sitting on the wrong table.
  // NOTE: this one is a REGRESSION control, not a proof of the fix — it also
  // passed before the fix. It is here because folding is the kind of change
  // that is easy to over-apply to the quoted side as well.
  test('quoted "Invoices" and unquoted invoices stay DISTINCT after folding', async () => {
    const db = new PGlite();
    await db.exec(`
      create table "Invoices" (id int, organization_id text);
      create table invoices (id int, organization_id text);
      alter table "Invoices" enable row level security;
      create policy p on "Invoices" using (true);
    `);
    // The migration declares the policy on the OTHER (lower-case) table.
    const files = [{ name: '001.sql', sql: `alter table invoices enable row level security;\ncreate policy p on invoices using (true);` }];
    const res = await drift({ query: query(db), files });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.deepEqual(res.violations.map((v) => v.where).sort(), ['public.Invoices', 'public.Invoices']);
  });
}

// ── 2. nested migration layouts ──────────────────────────────────────

function tempProject(files) {
  const root = mkdtempSync(join(tmpdir(), 'tg-rls-drift-'));
  for (const [rel, sql] of Object.entries(files)) {
    const full = join(root, ...rel.split('/'));
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, sql);
  }
  return root;
}

const fsdeps = { readdirSync, readFileSync, join };

test('collectSqlFiles finds Prisma-style <version>/migration.sql, keyed by relative path', () => {
  const dir = tempProject({
    '20240101000000_init/migration.sql': 'create policy p on t;',
    '20240202000000_drop/migration.sql': 'drop policy p on t;',
  });
  try {
    const files = collectSqlFiles(fsdeps, dir);
    assert.deepEqual(
      files.map((f) => f.name).sort(),
      ['20240101000000_init/migration.sql', '20240202000000_drop/migration.sql'],
      'basenames alone would collide — every Prisma migration is called migration.sql',
    );
    // and the relative path is what makes the create/drop replay deterministic
    assert.equal(parseDeclaredState(files).policies.has('public.t::p'), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('collectSqlFiles still reads a flat layout, and does NOT descend past the version dir', () => {
  const dir = tempProject({
    '001_init.sql': 'create policy a on t;',
    'v2/002.sql': 'create policy b on t;',
    'v2/nested/seed.sql': 'create policy too_deep on t;',
  });
  try {
    const names = collectSqlFiles(fsdeps, dir).map((f) => f.name).sort();
    assert.deepEqual(names, ['001_init.sql', 'v2/002.sql']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('run() SKIPS with a reason when the migrations dir holds no .sql — it never diffs against an empty declared set', async () => {
  const dir = tempProject({ 'README.md': '# migrations live in the ORM' });
  try {
    // A database URL is deliberately supplied: without the short-circuit this
    // would go on to connect and report every live policy as out-of-band.
    const res = await run({ migrationsDir: dir, url: 'postgres://unused.invalid/db' });
    assert.equal(res.skipped, true, JSON.stringify(res, null, 2));
    assert.equal(res.ok, true);
    assert.deepEqual(res.violations, []);
    assert.match(res.reason, /no \.sql files/);
    assert.match(res.reason, /NOT checked/, 'a skip must say what it could not check — a skip is never a pass');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('run() on a Prisma layout gets PAST file discovery (it reaches the database step)', async () => {
  const dir = tempProject({
    '20240101000000_init/migration.sql': `alter table invoices enable row level security;\ncreate policy tenant_iso on invoices using (true);`,
  });
  const saved = { tg: process.env.TENANT_GUARD_DATABASE_URL, db: process.env.DATABASE_URL };
  delete process.env.TENANT_GUARD_DATABASE_URL;
  delete process.env.DATABASE_URL;
  try {
    // With no URL, run() skips at the DATABASE step — which it can only reach
    // if discovery found the nested file. Before the fix it found 0 files and
    // (with a URL) failed the build on a database that matched its migrations.
    const res = await run({ migrationsDir: dir });
    assert.equal(res.skipped, true, JSON.stringify(res, null, 2));
    assert.match(res.reason, /no database configured/, 'discovery must have found the nested migration.sql');
  } finally {
    if (saved.tg !== undefined) process.env.TENANT_GUARD_DATABASE_URL = saved.tg;
    if (saved.db !== undefined) process.env.DATABASE_URL = saved.db;
    rmSync(dir, { recursive: true, force: true });
  }
});

if (PGlite) {
  test('a Prisma-layout project whose database matches its migrations is CLEAN', async () => {
    const sql = `create table invoices (id serial primary key, organization_id text);
      alter table invoices enable row level security;
      create policy tenant_iso on invoices using (organization_id = current_setting('app.t', true));`;
    const dir = tempProject({ '20240101000000_init/migration.sql': sql });
    try {
      const db = new PGlite();
      await db.exec(sql);
      // exactly the files run() now hands to drift()
      const res = await drift({ query: query(db), files: collectSqlFiles(fsdeps, dir) });
      assert.equal(res.ok, true, JSON.stringify(res, null, 2));
      assert.deepEqual(res.violations, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
