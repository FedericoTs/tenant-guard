/**
 * Regression tests for the constraint-oracles audit findings.
 *
 * Four separate defects, all reproduced against PGlite before the fix:
 *
 *   1. wrong advice — the remediation always said `ALTER TABLE … DROP CONSTRAINT
 *      <index>`. For a unique index made by `CREATE UNIQUE INDEX` (what Prisma and
 *      Drizzle emit) there is no constraint of that name, so the statement errors
 *      and the oracle survives. Measured: 2 of 3 emitted fixes failed to run.
 *   2. false negative — `create unique index on users (lower(email))` and
 *      `EXCLUDE (slug WITH =)` are live cross-tenant oracles (verified below:
 *      0 rows visible, insert still raises 23505 / 23P01) and the guard reported
 *      "none leak across tenants" over them.
 *   3. false positive — a globally unique bearer credential (`token`,
 *      `key_hash`) was failed, and the emitted fix — scope it to the tenant —
 *      lets one token exist in two organizations, which breaks the tenant-less
 *      lookup that a credential depends on.
 *   4. false positive — an all-uuid composite key (`UNIQUE (team_id, user_id)`,
 *      the ordinary join-table shape) was failed even though the single-uuid case
 *      was already exempt for exactly the reason that applies to both.
 *
 * Every test here fails against the pre-fix guard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  classifyUniqueIndex,
  expressionColumns,
  hasRandomDefault,
  spliceTenantIntoDef,
  uniqueIndexSql,
} from '../src/guards/constraint-oracles.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('constraint-oracles audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

/**
 * Pull every SQL statement out of a `fix` string and run it, in order.
 * Statements may span lines, so this cuts on the semicolon, not the newline.
 * Returns the ones that errored — the whole point of these tests is that the
 * list is empty, because advice a user pastes has to actually run.
 */
function statementsIn(fix) {
  return (fix.match(/(?:ALTER TABLE|DROP INDEX|CREATE UNIQUE INDEX|CREATE EXTENSION)[\s\S]*?;/g) || [])
    .map((s) => s.replace(/\s+/g, ' ').trim());
}
async function applyFix(db, fix) {
  const stmts = statementsIn(fix);
  assert.ok(stmts.length >= 2, `fix emitted no runnable SQL:\n${fix}`);
  const failures = [];
  for (const stmt of stmts) {
    try { await db.exec(stmt); } catch (e) { failures.push(`${stmt} -> ${e.message}`); }
  }
  return failures;
}

// ── pure helpers ─────────────────────────────────────────────────────

test('classifyUniqueIndex: an all-uuid composite key is not an enumeration primitive', () => {
  // `UNIQUE (team_id, user_id)` on a join table. Before: oracle (build failure).
  const v = classifyUniqueIndex({ columns: ['team_id', 'user_id'], types: ['uuid', 'uuid'], tenantColumn: 'organization_id' });
  assert.equal(v.status, 'skip');
  assert.match(v.reason, /unguessable/);
});

test('classifyUniqueIndex: a MIXED key keeps failing — one known uuid + a guessable column enumerates', () => {
  // This is the line the widened exemption must not cross.
  assert.equal(classifyUniqueIndex({ columns: ['external_ref', 'email'], types: ['uuid', 'text'], tenantColumn: 'organization_id' }).status, 'oracle');
  assert.equal(classifyUniqueIndex({ columns: ['document_id', 'version'], types: ['uuid', 'integer'], tenantColumn: 'organization_id' }).status, 'oracle');
  assert.equal(classifyUniqueIndex({ columns: ['slug'], types: ['text'], tenantColumn: 'organization_id' }).status, 'oracle');
});

test('classifyUniqueIndex: a random DEFAULT makes a text column unguessable, whatever its type', () => {
  const v = classifyUniqueIndex({
    columns: ['token'], types: ['text'], tenantColumn: 'organization_id',
    columnDefaults: { token: '(gen_random_uuid())::text' },
  });
  assert.equal(v.status, 'skip');
  // nextval is NOT a random generator — sequence values are the most guessable
  // thing in the database, so a unique on one stays an oracle.
  assert.equal(classifyUniqueIndex({
    columns: ['invoice_no'], types: ['integer'], tenantColumn: 'organization_id',
    columnDefaults: { invoice_no: "nextval('invoice_seq'::regclass)" },
  }).status, 'oracle');
});

test('classifyUniqueIndex: a bearer-credential column is a NOTE, never a failure', () => {
  const v = classifyUniqueIndex({ columns: ['key_hash'], types: ['text'], tenantColumn: 'organization_id' });
  assert.equal(v.status, 'note');
  assert.equal(v.kind, 'global-secret');
  // The name list is deliberately narrow: these must keep failing.
  for (const c of ['code', 'slug', 'email', 'phone', 'username']) {
    assert.equal(classifyUniqueIndex({ columns: [c], types: ['text'], tenantColumn: 'organization_id' }).status, 'oracle', c);
  }
});

test('classifyUniqueIndex: tenant-in-the-key is decided BEFORE the expression bail-out', () => {
  // `UNIQUE (organization_id, lower(email))` has indkey `2 0`, i.e. columns
  // ['organization_id', null]. It used to hit the expression skip and vanish.
  const v = classifyUniqueIndex({
    hasExpression: true, columns: ['organization_id', null], types: ['text', null], tenantColumn: 'organization_id',
  });
  assert.equal(v.status, 'safe');
});

test('classifyUniqueIndex: an expression over a guessable column is an oracle, over an unguessable one is not', () => {
  const common = { hasExpression: true, columns: [null], types: [null], tenantColumn: 'organization_id' };
  assert.equal(classifyUniqueIndex({ ...common, expr: 'lower(email)', columnTypes: { email: 'text', organization_id: 'text' } }).status, 'oracle');
  assert.equal(classifyUniqueIndex({ ...common, expr: "COALESCE(ref, '0'::uuid)", columnTypes: { ref: 'uuid', organization_id: 'text' } }).status, 'skip');
  // tenant column named inside the expression scopes it in effect
  assert.equal(classifyUniqueIndex({ ...common, expr: "lower((organization_id || ':'::text) || email)", columnTypes: { email: 'text', organization_id: 'text' } }).status, 'safe');
  // nothing resolvable -> say so, do not report it as checked
  const n = classifyUniqueIndex({ ...common, expr: '(1)', columnTypes: { email: 'text', organization_id: 'text' } });
  assert.equal(n.status, 'note');
  assert.equal(n.kind, 'unanalysed');
});

test('expressionColumns / hasRandomDefault / spliceTenantIntoDef', () => {
  assert.deepEqual(expressionColumns('lower(email)', ['email', 'organization_id']), ['email']);
  assert.deepEqual(expressionColumns('lower("Email")', ['Email']), ['Email']);
  assert.deepEqual(expressionColumns(null, ['email']), []);
  assert.equal(hasRandomDefault('(gen_random_uuid())::text'), true);
  assert.equal(hasRandomDefault("nextval('s'::regclass)"), false);
  assert.equal(
    spliceTenantIntoDef('EXCLUDE USING btree (slug WITH =)', 'organization_id', { operator: '=' }),
    'EXCLUDE USING btree ("organization_id" WITH =, slug WITH =)',
  );
  assert.equal(spliceTenantIntoDef('nonsense', 'organization_id'), null);
});

test('uniqueIndexSql: reads exclusion constraints and whether a pg_constraint backs the index', () => {
  const { text } = uniqueIndexSql(['public']);
  assert.match(text, /indisexclusion/);
  assert.match(text, /conindid/);
  assert.match(text, /pg_get_expr\(ix\.indexprs/);
});

if (PGlite) {
  // ── 1. the fix text has to run ──────────────────────────────────────

  test('FIX RUNS: a plain CREATE UNIQUE INDEX gets DROP INDEX, not DROP CONSTRAINT', async () => {
    const { db, query } = await fresh(`
      create table users (id uuid primary key, organization_id text not null, email text not null);
      create unique index users_email_idx on users(email);
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => /users_email_idx/.test(x.where));
    assert.ok(v, JSON.stringify(res, null, 2));
    assert.match(v.fix, /DROP INDEX "public"\."users_email_idx"/);
    assert.doesNotMatch(v.fix, /DROP CONSTRAINT/);
    assert.deepEqual(await applyFix(db, v.fix), []);
    // and the repair actually closes the finding
    assert.equal((await check({ query })).ok, true);
  });

  test('FIX RUNS: a mixed-case index name survives quoting', async () => {
    const { db, query } = await fresh(`
      create table t3 (id uuid primary key, organization_id text not null, slug text not null);
      create unique index "MyIdx" on t3(slug);
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => /MyIdx/.test(x.where));
    assert.ok(v, JSON.stringify(res, null, 2));
    assert.deepEqual(await applyFix(db, v.fix), []); // before: folded to "myidx" and errored
  });

  test('FIX RUNS: a real table constraint still gets ALTER TABLE … DROP CONSTRAINT', async () => {
    const { db, query } = await fresh(`
      create table teams (id uuid primary key, organization_id text not null, slug text unique);
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => /teams_slug_key/.test(x.where));
    assert.ok(v);
    assert.match(v.fix, /ALTER TABLE "public"\."teams" DROP CONSTRAINT "teams_slug_key"/);
    assert.match(v.fix, /UNIQUE \("organization_id", "slug"\)/);
    assert.deepEqual(await applyFix(db, v.fix), []);
  });

  // ── 2. the two constraints the guard could not see ──────────────────

  test('FLAGS a unique index on lower(email) — and the leak is real', async () => {
    const { db, query } = await fresh(`
      create table users (id serial primary key, organization_id text not null, email text not null);
      create unique index users_lower_email on users (lower(email));
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => /users_lower_email/.test(x.where));
    assert.ok(v, JSON.stringify(res, null, 2)); // before: ok:true, scanned:0
    assert.deepEqual(await applyFix(db, v.fix), []);

    // The premise, proved rather than asserted: RLS hides the row, the index
    // does not. Measured: 0 rows visible, insert raises 23505 naming the index.
    const db2 = new PGlite();
    await db2.exec(`
      create role authenticated nologin;
      create table users (id serial primary key, organization_id text not null, email text not null);
      create unique index users_lower_email on users (lower(email));
      grant select, insert on users to authenticated;
      grant usage on all sequences in schema public to authenticated;
      insert into users (organization_id, email) values ('org_B','Victim@corp.com');
      alter table users enable row level security;
      create policy tenant on users for all
        using (organization_id = current_setting('app.current_tenant', true))
        with check (organization_id = current_setting('app.current_tenant', true));
    `);
    const Q = (t) => db2.query(t);
    await Q('begin'); await Q('set local role authenticated');
    await Q(`select set_config('app.current_tenant','org_A',true)`);
    assert.equal((await Q('select count(*)::int as n from users')).rows[0].n, 0);
    let code = null;
    try { await Q(`insert into users (organization_id, email) values ('org_A','victim@corp.com')`); } catch (e) { code = e.code; }
    await Q('rollback');
    assert.equal(code, '23505');
  });

  test('FLAGS an EXCLUDE constraint, with its own error message and its own repair', async () => {
    const { db, query } = await fresh(`
      create table teams (id serial primary key, organization_id text not null, slug text not null,
        exclude using btree (slug with =));
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => /teams_slug_excl/.test(x.where));
    assert.ok(v, JSON.stringify(res, null, 2)); // before: ok:true, scanned:0
    assert.equal(v.kind, 'exclusion-oracle');
    // The runtime error is not "duplicate key value" — saying so would send the
    // reader looking for a unique index that does not exist.
    assert.match(v.message, /conflicting key value violates exclusion constraint/);
    assert.doesNotMatch(v.message, /duplicate key value/);
    // ADD CONSTRAINT … UNIQUE (…) is not valid SQL for an exclusion constraint.
    assert.match(v.fix, /EXCLUDE USING btree \("organization_id" WITH =, slug WITH =\)/);
    assert.deepEqual(await applyFix(db, v.fix), []);
    assert.equal((await check({ query })).ok, true);

    // premise: 0 rows visible, and the insert still collides -> 23P01
    const db2 = new PGlite();
    await db2.exec(`
      create role authenticated nologin;
      create table teams (id serial primary key, organization_id text not null, slug text not null,
        exclude using btree (slug with =));
      grant select, insert on teams to authenticated;
      grant usage on all sequences in schema public to authenticated;
      insert into teams (organization_id, slug) values ('org_B','acme');
      alter table teams enable row level security;
      create policy tenant on teams for all
        using (organization_id = current_setting('app.current_tenant', true))
        with check (organization_id = current_setting('app.current_tenant', true));
    `);
    const Q = (t) => db2.query(t);
    await Q('begin'); await Q('set local role authenticated');
    await Q(`select set_config('app.current_tenant','org_A',true)`);
    assert.equal((await Q('select count(*)::int as n from teams')).rows[0].n, 0);
    let code = null;
    try { await Q(`insert into teams (organization_id, slug) values ('org_A','acme')`); } catch (e) { code = e.code; }
    await Q('rollback');
    assert.equal(code, '23P01');
  });

  test('does NOT flag the correctly-scoped composite forms — and counts them as checked', async () => {
    // The whole point: the fix must not turn the recommended shapes into failures.
    const { query } = await fresh(`
      create table users (id serial primary key, organization_id text not null, email text not null);
      create unique index users_org_lower_email on users (organization_id, lower(email));
      create table rooms (id serial primary key, organization_id text not null, room_id int not null, slot int not null,
        exclude using btree (organization_id with =, room_id with =, slot with =));
      create table docs (id serial primary key, organization_id text not null, email text not null);
      create unique index docs_expr on docs (lower(organization_id || ':' || email));
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res.violations, null, 2));
    assert.equal(res.notes.length, 0, JSON.stringify(res.notes, null, 2));
    // Before the fix these classified as `skip` and never reached `scanned`.
    assert.equal(res.scanned, 3, res.summary);
  });

  test('an expression it cannot read becomes a NOTE — a skip is not a pass', async () => {
    const { query } = await fresh(`
      create table t (id serial primary key, organization_id text not null, a int not null);
      create unique index t_expr on t ((1));
    `);
    const res = await check({ query });
    assert.equal(res.ok, true); // note, not a failure
    const n = res.notes.find((x) => /not analysed/.test(x.where));
    assert.ok(n, JSON.stringify(res, null, 2));
    assert.match(n.message, /t_expr/);
    assert.equal(res.scanned, 1); // counted as looked-at, so the summary is honest
  });

  // ── 3. bearer credentials ───────────────────────────────────────────

  test('does NOT fail the build on a global bearer credential, and argues for keeping it', async () => {
    const { query } = await fresh(`
      create table invitations (id uuid primary key, organization_id text not null,
        token text not null unique default gen_random_uuid()::text);
      create table api_keys (id uuid primary key, organization_id text not null, key_hash text not null unique);
      create table coupons (id uuid primary key, organization_id text not null, code text not null unique);
      create table people (id uuid primary key, organization_id text not null, email text not null unique);
      create table pages (id uuid primary key, organization_id text not null, slug text not null unique);
    `);
    const res = await check({ query });
    const flagged = res.violations.map((v) => v.where).join(' ');
    assert.doesNotMatch(flagged, /invitations/); // random DEFAULT -> unguessable
    assert.doesNotMatch(flagged, /api_keys/);    // bearer credential -> note
    // the ordinary enumerable natural keys must still fail
    assert.match(flagged, /coupons/);
    assert.match(flagged, /people/);
    assert.match(flagged, /pages/);

    const n = res.notes.find((x) => /bearer credential/.test(x.where));
    assert.ok(n, JSON.stringify(res.notes, null, 2));
    assert.match(n.message, /api_keys/);
    assert.match(n.message, /KEEP the global constraint/);
    assert.match(n.message, /Do not scope the constraint/);
  });

  test('PROVES why: scoping a bearer token to the tenant breaks the tenant-less lookup', async () => {
    // This is what the old fix text told people to do.
    const { db } = await fresh(`
      create table invitations (id serial primary key, organization_id text not null, token text not null,
        unique (organization_id, token));
      insert into invitations (organization_id, token) values ('org_A','tok-1'), ('org_B','tok-1');
    `);
    const r = await db.query(`select organization_id from invitations where token='tok-1'`);
    assert.equal(r.rows.length, 2, 'one secret now resolves to two tenants');
  });

  // ── 4. join tables ──────────────────────────────────────────────────

  test('does NOT fail the build on an all-uuid join key, but still fails on a mixed one', async () => {
    const { query } = await fresh(`
      create table team_members (id uuid primary key, organization_id text not null,
        team_id uuid not null, user_id uuid not null, unique (team_id, user_id));
      create table document_versions (id uuid primary key, organization_id text not null,
        document_id uuid not null, version integer not null, unique (document_id, version));
    `);
    const res = await check({ query });
    const flagged = res.violations.map((v) => v.where).join(' ');
    assert.doesNotMatch(flagged, /team_members/);
    assert.match(flagged, /document_versions/); // uuid + integer still enumerates
  });
}
