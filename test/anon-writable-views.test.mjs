/**
 * The view write surface — the reported P0, measured at runtime.
 *
 * `updatable-view-writethrough` catches this statically, from migration text.
 * This is the other half: what the database ACTUALLY grants right now, on
 * objects that already exist. The reported bug arrived that way — an
 * `ALTER DEFAULT PRIVILEGES ... ON TABLES` armed a view created afterwards, so
 * no migration reads like a security change and the grant is only visible in
 * the catalog.
 *
 * Before this, `anon-writes` scanned `relkind in ('r','p')` and returned OK on a
 * database where `anon` could DELETE through a view over an RLS-protected table.
 * Reproduced below.
 *
 * The calibration tests are the ones that matter. Grants alone do not
 * distinguish a writable view from a reporting one: a view with an aggregate or
 * a join carries the same `has_table_privilege` answer and passes nothing
 * through, so a grant-based check fires on every reporting view in the schema.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  planViewSurface,
  runsAsOwner,
  viewUpdateSql,
  violationForView,
  check,
} from '../src/guards/anon-writes.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('anon writable views (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure ─────────────────────────────────────────────────────────────

const row = (o) => ({
  schema: 'public', table: 'v', relkind: 'v', owner_role: 'postgres',
  updatable_mask: 28, security_invoker: 'false',
  can_insert: true, can_update: true, can_delete: true, probe_col: 'id', ...o,
});

test('runsAsOwner: the DEFAULT is owner — which is the dangerous one', () => {
  assert.equal(runsAsOwner({ security_invoker: 'false' }), true);
  assert.equal(runsAsOwner({}), true);
  assert.equal(runsAsOwner({ security_invoker: 'true' }), false);
});

test('planViewSurface skips a view nothing can be written through', () => {
  // mask 0 = aggregate or join. Same grants, no write-through: a grant-based
  // check fires here and this one must not.
  assert.deepEqual(planViewSurface([row({ updatable_mask: 0 })]), []);
});

test('planViewSurface skips a security_invoker view — the base RLS applies', () => {
  assert.deepEqual(planViewSurface([row({ security_invoker: 'true' })]), []);
});

test('planViewSurface skips a view with no write privilege at all', () => {
  assert.deepEqual(planViewSurface([row({ can_insert: false, can_update: false, can_delete: false })]), []);
});

test('planViewSurface keeps the one that is all three', () => {
  const plan = planViewSurface([row({})]);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].probeCol, 'id');
});

test('the allowlist takes a bare name or a qualified one', () => {
  assert.deepEqual(planViewSurface([row({})], ['v']), []);
  assert.deepEqual(planViewSurface([row({})], ['public.v']), []);
});

test('viewUpdateSql rewrites a column to itself and quotes it', () => {
  assert.equal(viewUpdateSql('public', 'v', 'we"ird'), 'update "public"."v" set "we""ird" = "we""ird"');
});

test('the fix offers BOTH the revoke and security_invoker, and names the cause', () => {
  const v = violationForView({ schema: 'public', table: 'pp', ownerRole: 'postgres' }, ['UPDATE'], 'anon');
  assert.match(v.fix, /REVOKE INSERT, UPDATE, DELETE/);
  assert.match(v.fix, /security_invoker = true/);
  assert.match(v.message, /ALTER DEFAULT PRIVILEGES/);
});

if (PGlite) {
  async function fresh() {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin; create role authenticated nologin;
      grant usage on schema public to anon, authenticated;

      -- the mechanism: it arms every table AND view created afterwards
      alter default privileges in schema public
        grant select, insert, update, delete on tables to anon, authenticated;

      create table profiles (id int primary key, user_id text, display_name text, email text);
      insert into profiles values (1, 'u1', 'Ada', 'ada@x.com');
      alter table profiles enable row level security;
      create policy own on profiles for all to authenticated
        using (user_id = current_setting('app.uid', true))
        with check (user_id = current_setting('app.uid', true));

      create view public_profiles as select id, display_name from profiles;
      create view profile_counts  as select user_id, count(*) n from profiles group by 1;
      create view safe_profiles with (security_invoker = true) as select id from profiles;
    `);
    return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
  }

  test('DEMONSTRATES it: anon writes through the view into an RLS-protected table', async () => {
    const { db } = await fresh();
    await db.query('begin');
    await db.query('set local role anon');
    const res = await db.query('update public_profiles set id = id');
    await db.query('rollback');
    assert.ok((res.rowCount ?? res.affectedRows) > 0, 'the base table RLS was never consulted');
  });

  test('CATCHES it — the case that used to report OK', async () => {
    const { query } = await fresh();
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => /public_profiles/.test(x.where));
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.kind, 'anon-writable-view');
  });

  test('says nothing about the aggregate view — no write passes through it', async () => {
    const { query } = await fresh();
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.violations.some((x) => /profile_counts/.test(x.where)), false,
      'same grants, no write-through: a grant-based check would fire here');
  });

  test('says nothing about the security_invoker view — the base RLS holds', async () => {
    const { query } = await fresh();
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.violations.some((x) => /safe_profiles/.test(x.where)), false);
  });

  test('the recommended fix actually clears it', async () => {
    const { db, query } = await fresh();
    await db.exec('alter view public_profiles set (security_invoker = true);');
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.violations.some((x) => /public_profiles/.test(x.where)), false, JSON.stringify(res, null, 2));
  });

  test('and so does the revoke', async () => {
    const { db, query } = await fresh();
    await db.exec('revoke insert, update, delete on public_profiles from anon, authenticated;');
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.violations.some((x) => /public_profiles/.test(x.where)), false, JSON.stringify(res, null, 2));
  });

  test('the probe leaves the data alone', async () => {
    const { db, query } = await fresh();
    await check({ query, config: { role: 'anon' } });
    const rows = await db.query('select id, display_name from profiles order by id');
    assert.deepEqual(rows.rows, [{ id: 1, display_name: 'Ada' }]);
  });
}
