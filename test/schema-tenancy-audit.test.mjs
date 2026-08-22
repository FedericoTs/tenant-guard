/**
 * schema-tenancy — regressions found by audit.
 *
 * Three of these are cases where the guard printed an affirmative all-clear over
 * a read it had never attempted, and two are remediation text that does not do
 * what it says when pasted. Each test below fails against the pre-audit guard.
 *
 * The calibration tests at the bottom matter as much as the rest: the fix for
 * "probe every shape group" widens what gets probed, so a role that legitimately
 * reaches one schema in each of two unrelated groups must stay green.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  classifySchemaReach,
  schemaScopingFix,
  inferTenantSchemas,
  inferTenantSchemaGroups,
  findNearMissPairs,
  groupProbeCandidates,
  probeTargetsSql,
} from '../src/guards/schema-tenancy.mjs';

// ── pure logic ───────────────────────────────────────────────────────

test('infer: EVERY repeated shape is a group, not just the largest', () => {
  const rows = [
    { schema: 't1', tables: ['docs'] },
    { schema: 't2', tables: ['docs'] },
    { schema: 't3', tables: ['docs'] },
    { schema: 't4', tables: ['docs', 'extra'] },
    { schema: 't5', tables: ['docs', 'extra'] },
  ];
  // The old code returned only ['t1','t2','t3'] and discarded t4/t5 entirely.
  assert.deepEqual(inferTenantSchemaGroups(rows), [['t1', 't2', 't3'], ['t4', 't5']]);
  // The single-best-guess helper still answers the old question.
  assert.deepEqual(inferTenantSchemas(rows), ['t1', 't2', 't3']);
});

test('infer: an ordinary multi-schema database still produces NO groups', () => {
  const rows = [
    { schema: 'public', tables: ['invoices'] },
    { schema: 'analytics', tables: ['rollups'] },
    { schema: 'audit', tables: ['events'] },
  ];
  assert.deepEqual(inferTenantSchemaGroups(rows), []);
});

test('near-miss: a drifted pair is NAMED, and still not grouped as tenants', () => {
  const rows = [
    { schema: 'tenant_a', tables: ['docs', 'notes'] },
    { schema: 'tenant_b', tables: ['docs'] },
    { schema: 'public', tables: ['migrations'] },
  ];
  assert.deepEqual(inferTenantSchemaGroups(rows), [], 'exact-set grouping must stay exact');
  const near = findNearMissPairs(rows);
  assert.equal(near.length, 1);
  assert.deepEqual([near[0].a, near[0].b], ['tenant_a', 'tenant_b']);
  assert.equal(near[0].shared, 1);
  assert.equal(near[0].of, 2);
});

test('near-miss: unrelated schemas sharing nothing are not reported', () => {
  const rows = [
    { schema: 'analytics', tables: ['rollups'] },
    { schema: 'audit', tables: ['events'] },
  ];
  assert.deepEqual(findNearMissPairs(rows), []);
});

test('probe target: the catalog picks the table, table-grant beats column-grant beats nothing', () => {
  const sql = probeTargetsSql(['s'], 'app_role');
  assert.match(sql.text, /has_table_privilege\(\$2::text/);
  assert.match(sql.text, /has_any_column_privilege\(\$2::text/);
  assert.deepEqual(sql.values, [['s'], 'app_role']);

  // Measured in pglite: `grant select (id) on s.c` reads tbl=false / col=true,
  // and `select count(*) from s.c` then succeeds — so a column grant is a valid
  // probe target, just a worse one than a full table grant.
  const ordered = groupProbeCandidates([
    { schema: 's', table: 'aaa_none', tbl_priv: false, col_priv: false },
    { schema: 's', table: 'ccc_column', tbl_priv: false, col_priv: true },
    { schema: 's', table: 'zzz_table', tbl_priv: true, col_priv: true },
  ]).get('s');
  assert.deepEqual(ordered.map((c) => c.table), ['zzz_table', 'ccc_column', 'aaa_none']);
  assert.deepEqual(ordered.map((c) => c.privileged), [true, true, false]);
});

test('probe target: string booleans from drivers that return t/f are handled', () => {
  const ordered = groupProbeCandidates([
    { schema: 's', table: 'a', tbl_priv: 'f', col_priv: 'f' },
    { schema: 's', table: 'b', tbl_priv: 't', col_priv: 't' },
  ]).get('s');
  assert.deepEqual(ordered.map((c) => c.table), ['b', 'a']);
});

// ── remediation text ─────────────────────────────────────────────────

const LEAK = {
  role: 'authenticated',
  tenantSchemas: ['tenant_a', 'tenant_b'],
  reachable: ['tenant_a', 'tenant_b'],
  probed: [{ schema: 'tenant_a', table: 'docs', rows: 1 }, { schema: 'tenant_b', table: 'docs', rows: 1 }],
};

test('fix: revokes from the grantees that HOLD the access, not from the role it just created', () => {
  const fix = classifySchemaReach(LEAK).fix;
  // The old text was `REVOKE ALL ON SCHEMA tenant_b FROM tenant_a_app;` — a
  // grantee that by construction holds nothing, so it was inert in every case.
  assert.doesNotMatch(fix, /REVOKE[^\n]*FROM tenant_a_app/);
  assert.match(fix, /REVOKE ALL ON ALL TABLES IN SCHEMA tenant_a, tenant_b FROM PUBLIC, "authenticated";/);
  assert.match(fix, /REVOKE ALL ON ALL SEQUENCES IN SCHEMA tenant_a, tenant_b FROM PUBLIC, "authenticated";/);
  assert.match(fix, /REVOKE ALL ON SCHEMA tenant_a, tenant_b FROM PUBLIC, "authenticated";/);
});

test('fix: grants sequences and records what the NEXT migration creates', () => {
  const fix = classifySchemaReach(LEAK).fix;
  // serial inserts fail on the day the old fix is applied: 42501 "permission
  // denied for sequence ser_id_seq".
  assert.match(fix, /GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA tenant_a TO tenant_a_app;/);
  // ON ALL TABLES is point-in-time; without this the next migration's tables are
  // unreadable to the tenant role.
  assert.match(fix, /ALTER DEFAULT PRIVILEGES FOR ROLE <your-migration-role> IN SCHEMA tenant_a/);
  assert.match(fix, /GRANT USAGE, SELECT ON SEQUENCES TO tenant_a_app;/);
  // FOR ROLE is not optional: without it the defaults are recorded only for
  // whoever ran the statement.
  assert.doesNotMatch(fix, /ALTER DEFAULT PRIVILEGES IN SCHEMA/);
});

test('fix: schema names that are not plain identifiers are quoted so the SQL parses', () => {
  const fix = schemaScopingFix({ role: 'app_user', reachable: ['org-123', 'org 456'] });
  assert.match(fix, /GRANT USAGE ON SCHEMA "org-123" TO tenant_a_app;/);
  assert.match(fix, /REVOKE ALL ON SCHEMA "org-123", "org 456" FROM PUBLIC, "app_user";/);
});

test('fix: PUBLIC is a keyword, so a role literally named public is not named twice', () => {
  const fix = schemaScopingFix({ role: 'public', reachable: ['tenant_a', 'tenant_b'] });
  assert.match(fix, /FROM PUBLIC;/);
  assert.doesNotMatch(fix, /PUBLIC, "public"/);
});

// ── integration ──────────────────────────────────────────────────────

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('schema-tenancy audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec('create role app_role nologin;');
  await db.exec(setup);
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

/** Read `sql` as `role` in a transaction that is always rolled back. */
async function asRole(db, role, sql) {
  await db.exec('begin');
  try {
    await db.exec(`set local role ${role}`);
    const r = await db.query(sql);
    await db.exec('rollback');
    return { ok: true, rows: r.rows };
  } catch (e) {
    try { await db.exec('rollback'); } catch { /* ignore */ }
    return { ok: false, err: e.message };
  }
}

if (PGlite) {
  test('CATCHES a leak in a shape group that is not the largest one', async () => {
    // t1,t2,t3 share {docs} and are ungranted; t4,t5 share {docs,extra} and are
    // both readable. The old guard kept only the biggest group and reported
    // "cannot reach any of the 3 tenant schema(s)".
    const { db, query } = await fresh(`
      create schema t1; create schema t2; create schema t3; create schema t4; create schema t5;
      create table t1.docs(id int); create table t2.docs(id int); create table t3.docs(id int);
      create table t4.docs(id int); create table t4.extra(id int);
      create table t5.docs(id int); create table t5.extra(id int);
      insert into t4.docs values (4); insert into t5.docs values (5);
      grant usage on schema t4, t5 to app_role;
      grant select on all tables in schema t4 to app_role;
      grant select on all tables in schema t5 to app_role;
    `);
    // The leak is real, independently of the guard.
    const live = await asRole(db, 'app_role', 'select (select count(*) from t4.docs) a, (select count(*) from t5.docs) b');
    assert.equal(live.ok, true, JSON.stringify(live));

    const res = await check({ query, config: { role: 'app_role' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'schema-reach');
    assert.deepEqual(v.reachable.sort(), ['t4', 't5']);
    assert.equal(res.scanned, 5, 'both groups are in scope, not just the biggest');
  });

  test('CATCHES a leak reachable only through a table that does not sort first', async () => {
    const { db, query } = await fresh(`
      create schema tenant_a; create schema tenant_b;
      create table tenant_a.aaa_meta(id int); create table tenant_a.zzz_docs(id int, body text);
      create table tenant_b.aaa_meta(id int); create table tenant_b.zzz_docs(id int, body text);
      insert into tenant_a.zzz_docs values (1,'a');
      insert into tenant_b.zzz_docs values (2,'b-secret');
      grant usage on schema tenant_a, tenant_b to app_role;
      grant select on all tables in schema tenant_a to app_role;
      grant select on tenant_b.zzz_docs to app_role;   -- NOT aaa_meta, which sorts first
    `);
    const live = await asRole(db, 'app_role', 'select * from tenant_b.zzz_docs');
    assert.deepEqual(live.rows, [{ id: 2, body: 'b-secret' }]);

    const res = await check({ query, config: { role: 'app_role' } });
    // Old behaviour: ok=true, "proven scoped to one tenant", notes empty.
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.deepEqual(res.violations[0].reachable.sort(), ['tenant_a', 'tenant_b']);
    assert.match(res.violations[0].message, /proven by reading from/);
  });

  test('a column-level grant is reachability too', async () => {
    const { query } = await fresh(`
      create schema tenant_a; create schema tenant_b;
      create table tenant_a.aaa_meta(id int); create table tenant_a.zzz_docs(id int, body text);
      create table tenant_b.aaa_meta(id int); create table tenant_b.zzz_docs(id int, body text);
      grant usage on schema tenant_a, tenant_b to app_role;
      grant select on all tables in schema tenant_a to app_role;
      grant select (id) on tenant_b.zzz_docs to app_role;
    `);
    const res = await check({ query, config: { role: 'app_role' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
  });

  test('a fleet that drifted by one table is NOTED, not waved through', async () => {
    const { db, query } = await fresh(`
      create schema tenant_a; create schema tenant_b;
      create table tenant_a.docs(id int, body text);
      create table tenant_a.notes(id int);
      create table tenant_b.docs(id int, body text);
      insert into tenant_a.docs values (1,'a'); insert into tenant_b.docs values (2,'b-secret');
      grant usage on schema tenant_a, tenant_b to app_role;
      grant select on all tables in schema tenant_a to app_role;
      grant select on all tables in schema tenant_b to app_role;
    `);
    const live = await asRole(db, 'app_role', 'select (select count(*) from tenant_a.docs) a, (select count(*) from tenant_b.docs) b');
    assert.equal(live.ok, true, 'the role really does read both tenants');

    const res = await check({ query, config: { role: 'app_role' } });
    // Still a pass — inference stays exact, because a similarity score would
    // start failing CI on reporting_v1/reporting_v2. But it no longer claims
    // there is nothing here.
    assert.equal(res.ok, true);
    assert.equal(res.skipped, true);
    assert.doesNotMatch(res.reason, /no schema-per-tenant layout detected/);
    const note = res.notes.find((n) => /tenant_a/.test(n.where) && /tenant_b/.test(n.where));
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /schemaPattern/);

    // ...and the escape hatch the note points at actually closes it.
    const withPattern = await check({ query, config: { role: 'app_role', schemaPattern: '^tenant_' } });
    assert.equal(withPattern.ok, false, JSON.stringify(withPattern, null, 2));
  });

  test('the emitted fix, pasted as-is, closes the leak and leaves the tenant working', async () => {
    const { db, query } = await fresh(`
      create role authenticated nologin;
      create schema tenant_a; create schema tenant_b;
      create table tenant_a.docs(id int, body text);
      create table tenant_b.docs(id int, body text);
      create table tenant_a.ser(id serial primary key, v int);
      create table tenant_b.ser(id serial primary key, v int);
      insert into tenant_a.docs values (1,'a'); insert into tenant_b.docs values (2,'b-secret');
      grant usage on schema tenant_a, tenant_b to public;
      grant select on all tables in schema tenant_a to public;
      grant select on all tables in schema tenant_b to public;
    `);
    const res = await check({ query, config: { role: 'authenticated' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));

    // Pull the SQL out of the fix and run it. The only substitution is the
    // migration-role placeholder, which is a placeholder on purpose: guessing it
    // would produce an ALTER DEFAULT PRIVILEGES that silently records nothing.
    const owner = (await db.query('select current_user as u')).rows[0].u;
    const sql = res.violations[0].fix
      .split('\n')
      .filter((l) => /^ {8}\S/.test(l) || /^ {10}GRANT/.test(l))
      .map((l) => l.trim())
      .filter((l) => !l.startsWith('--'))
      .join('\n')
      .replaceAll('<your-migration-role>', owner);
    assert.match(sql, /^CREATE ROLE tenant_a_app;/);
    await db.exec(sql);

    assert.equal((await asRole(db, 'tenant_a_app', 'select * from tenant_a.docs')).ok, true, 'tenant keeps its own schema');
    assert.equal((await asRole(db, 'tenant_a_app', 'insert into tenant_a.ser(v) values (1)')).ok, true, 'serial insert works');
    assert.equal((await asRole(db, 'tenant_a_app', 'select * from tenant_b.docs')).ok, false, 'other tenant is closed');
    assert.equal((await asRole(db, 'authenticated', 'select * from tenant_b.docs')).ok, false, 'the leaking role is closed');

    // A table created after the fix is inherited, which the old ON ALL TABLES
    // sweep did not cover.
    await db.exec('create table tenant_a.newer (id serial primary key, v int)');
    assert.equal((await asRole(db, 'tenant_a_app', 'insert into tenant_a.newer(v) values (9)')).ok, true, 'next migration inherits');

    const after = await check({ query, config: { role: 'tenant_a_app', schemaPattern: '^tenant_' } });
    assert.equal(after.ok, true, JSON.stringify(after, null, 2));
  });

  // ── calibration: the widened probe must not start crying wolf ──────

  test('does NOT fire on one schema reached in each of two unrelated shape groups', async () => {
    // staging/prod and reporting_v1/reporting_v2 are both "repeated shapes", and
    // the app role reaches exactly one of each. Merging the groups would call
    // this a two-tenant leak; per-group classification does not.
    const { query } = await fresh(`
      create schema staging; create schema prod;
      create table staging.docs(id int); create table prod.docs(id int);
      create schema reporting_v1; create schema reporting_v2;
      create table reporting_v1.rollups(id int); create table reporting_v1.dims(id int);
      create table reporting_v2.rollups(id int); create table reporting_v2.dims(id int);
      grant usage on schema prod, reporting_v2 to app_role;
      grant select on all tables in schema prod to app_role;
      grant select on all tables in schema reporting_v2 to app_role;
    `);
    const res = await check({ query, config: { role: 'app_role' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /at most one schema in each shape group/);
  });

  test('still PROVES a correct per-tenant role, with several tables and mixed grants', async () => {
    const { query } = await fresh(`
      create schema tenant_a; create schema tenant_b;
      create table tenant_a.aaa_meta(id int); create table tenant_a.zzz_docs(id int);
      create table tenant_b.aaa_meta(id int); create table tenant_b.zzz_docs(id int);
      create role tenant_a_app nologin;
      grant usage on schema tenant_a to tenant_a_app;
      grant select on all tables in schema tenant_a to tenant_a_app;
    `);
    const res = await check({ query, config: { role: 'tenant_a_app' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /proven scoped to one tenant/);
  });

  test('schema USAGE with no table grant anywhere is still not access', async () => {
    const { query } = await fresh(`
      create schema tenant_a; create schema tenant_b;
      create table tenant_a.aaa_meta(id int); create table tenant_a.zzz_docs(id int);
      create table tenant_b.aaa_meta(id int); create table tenant_b.zzz_docs(id int);
      grant usage on schema tenant_a, tenant_b to app_role;
      grant select on all tables in schema tenant_a to app_role;
    `);
    const res = await check({ query, config: { role: 'app_role' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /proven scoped to one tenant/);
  });
}
