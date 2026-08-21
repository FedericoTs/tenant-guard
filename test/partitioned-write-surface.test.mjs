/**
 * Partitioned parents in the anon write surface — a live false negative.
 *
 * `anon-writes` and `rls-drift` selected `relkind = 'r'`, so a PARTITIONED
 * parent (`relkind = 'p'`) was never examined. That is where the grant usually
 * lives: you `GRANT ... ON events TO anon` once, not on every leaf. Reproduced
 * before the fix — anon updated every row through the parent while the guard
 * reported CLEAN.
 *
 * This is the same class as threat-model §4.7, which was found and fixed in
 * `rls-proof` and never fixed in these two. Worth a dedicated test for exactly
 * that reason: the class recurs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check as checkAnonWrites } from '../src/guards/anon-writes.mjs';
import { drift } from '../src/guards/rls-drift.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('partitioned write surface (pglite not installed — skipped)', { skip: true }, () => {});
}

const query = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

if (PGlite) {
  test('CATCHES a write grant held on a partitioned PARENT', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table events (id int, v int) partition by range (id);
      create table events_a partition of events for values from (1) to (100);
      insert into events values (1, 1), (2, 2);
      grant select, insert, update, delete on events to anon;   -- the PARENT only
    `);

    // The write really does go through: this is what the guard must not miss.
    await db.query('begin');
    await db.query('set local role anon');
    const wrote = await db.query('update events set v = v');
    await db.query('rollback');
    assert.ok((wrote.rowCount ?? wrote.affectedRows) > 0, 'anon can write through the parent');

    const res = await checkAnonWrites({ query: query(db), config: { role: 'anon' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(
      res.violations.some((v) => /events\b/.test(v.where)),
      `the parent must be reported: ${JSON.stringify(res.violations.map((v) => v.where))}`,
    );
  });

  test('rls-drift sees RLS enabled on a partitioned parent too', async () => {
    const db = new PGlite();
    await db.exec(`
      create table events (id int, organization_id text) partition by range (id);
      create table events_a partition of events for values from (1) to (100);
      alter table events enable row level security;
      create policy p on events using (true);
    `);
    // Only the RLS-ENABLED arm was blind — `pg_policies` is not relkind-filtered,
    // so the policy arm always saw the parent. And the flag does not propagate:
    // `events_a` has relrowsecurity = false, so the parent is the ONLY place this
    // fact lives. Miss it and the on/off state of the isolation is unreportable.
    const res = await drift({ query: query(db), files: [{ name: '001_init.sql', sql: 'create table events (id int);' }] });
    const rlsArm = res.violations.filter((v) => /ROW LEVEL SECURITY is enabled/.test(v.message));
    assert.deepEqual(
      rlsArm.map((v) => v.where),
      ['public.events'],
      `the partitioned parent's RLS state must be reported: ${JSON.stringify(res.violations, null, 2)}`,
    );
  });
}
