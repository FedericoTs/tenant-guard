/**
 * anon-writes end-to-end, against a REAL Postgres (embedded via pglite).
 *
 * The two tests that carry the design: it FLAGS a table anon can write (the
 * cache-poisoning class), and it does NOT false-flag a table whose policy is
 * `TO public` but gates on auth state (`USING (… = current_setting('app.uid'))`)
 * — the exact case a catalog-only check gets wrong. Plus the unambiguous RLS-off
 * grant, the allowlist, and the BYPASSRLS abort.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/anon-writes.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('anon-writes integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role anon nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('FLAGS an anon-writable table under RLS (the cache-poisoning class)', async () => {
    const { query } = await fresh(`
      create table cache (id serial primary key, val text);
      grant select, insert, update, delete on cache to anon;
      insert into cache (val) values ('a'), ('b');
      alter table cache enable row level security;
      create policy pub_read  on cache for select to anon using (true);
      create policy pub_write on cache for update to anon using (true) with check (true); -- BUG: anon can rewrite
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'public.cache');
    assert.ok(v, JSON.stringify(res.violations));
    assert.deepEqual(v.commands, ['UPDATE']); // update open, delete has no policy
    assert.match(v.message, /a policy permits it/);
  });

  test('does NOT false-flag a well-secured policy that gates on auth state', async () => {
    const { query } = await fresh(`
      create table docs (id serial primary key, user_id text, body text);
      grant select, update, delete on docs to anon;
      insert into docs (user_id, body) values ('u1','x'), ('u2','y');
      alter table docs enable row level security;
      -- TO public, but the USING evaluates false for an unauthenticated caller.
      create policy owner_read   on docs for select to public using (user_id = current_setting('app.uid', true));
      create policy owner_update on docs for update to public using (user_id = current_setting('app.uid', true));
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2)); // the probe evaluates USING -> anon affects 0 rows
    assert.equal(res.violations.length, 0);
  });

  test('FLAGS unambiguously when RLS is OFF and anon has a write grant', async () => {
    const { query } = await fresh(`
      create table events (id serial primary key, kind text);
      grant insert, update on events to anon;
      -- RLS never enabled: the grant is the whole story
    `);
    const res = await check({ query });
    assert.equal(res.ok, false);
    const v = res.violations.find((x) => x.where === 'public.events');
    assert.deepEqual(v.commands, ['INSERT', 'UPDATE']);
    assert.match(v.message, /RLS is OFF/);
  });

  test('allowlist silences an intentionally public-write table', async () => {
    const { query } = await fresh(`
      create table contact_form (id serial primary key, email text);
      grant insert on contact_form to anon;
    `);
    const res = await check({ query, config: { allowlist: ['public.contact_form'] } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('clean: a table with no anon write access passes', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, org text);
      grant select on invoices to anon;         -- read only
      insert into invoices (org) values ('a');
      alter table invoices enable row level security;
      create policy r on invoices for select to anon using (true);
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('SELF-CHECK: a BYPASSRLS anon aborts (results would be meaningless)', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon bypassrls nologin;
      create table t (id serial primary key, val text);
      grant select, update on t to anon;
      insert into t (val) values ('a');
      alter table t enable row level security;
    `);
    const query = (q, v) => db.query(q, Array.isArray(v) && v.length ? v : undefined);
    const res = await check({ query });
    assert.equal(res.ok, false);
    assert.ok(res.violations.some((v) => /BYPASSES RLS/.test(v.message)), JSON.stringify(res.violations));
  });
}
