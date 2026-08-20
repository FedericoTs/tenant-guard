/**
 * constraint-oracles (threat-model 2.11) against a real Postgres.
 *
 * RLS hides rows; it does not hide constraints, and constraints are enforced
 * below it. The test that matters most is the pair: `UNIQUE (email)` on a
 * tenant-scoped table is an oracle, while `UNIQUE (organization_id, email)` on
 * the same table is not — because the second can hold the same email once per
 * tenant, so an insert collision tells you nothing about anyone else.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/constraint-oracles.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('constraint-oracles integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('FLAGS a globally UNIQUE natural key on a tenant table (the enumeration oracle)', async () => {
    const { query } = await fresh(`
      create table users (
        id uuid primary key default gen_random_uuid(),
        organization_id text not null,
        email text not null unique          -- global: leaks existence across tenants
      );
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'unique-oracle');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /does not include "organization_id"/);
    assert.match(v.message, /checked BELOW row-level security/);
    assert.match(v.message, /ON CONFLICT DO NOTHING/);
    assert.match(v.fix, /UNIQUE \("organization_id", "email"\)/);
  });

  test('does NOT flag the same key when it is scoped to the tenant', async () => {
    const { query } = await fresh(`
      create table users (
        id uuid primary key default gen_random_uuid(),
        organization_id text not null,
        email text not null,
        unique (organization_id, email)     -- the fix: one such email PER TENANT
      );
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('does NOT flag a primary key, nor a single UUID unique column (unguessable)', async () => {
    const { query } = await fresh(`
      create table docs (
        id uuid primary key default gen_random_uuid(),
        organization_id text not null,
        external_ref uuid unique             -- random: "does it exist" answers nothing
      );
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('does NOT flag a table with no tenant column (global reference data)', async () => {
    const { query } = await fresh(`
      create table countries (code text primary key, name text not null unique);
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('skips an expression index rather than guessing at its columns', async () => {
    const { query } = await fresh(`
      create table users (id serial primary key, organization_id text not null, email text not null);
      create unique index users_lower_email on users (lower(email));
    `);
    const res = await check({ query });
    // We cannot read the columns of an expression index from indkey, so we say
    // nothing rather than inventing a verdict in either direction.
    assert.equal(res.violations.some((v) => /users_lower_email/.test(v.where)), false, JSON.stringify(res.violations, null, 2));
  });

  test('reports loose foreign keys as a NOTE, never a build failure', async () => {
    const { query } = await fresh(`
      create table users (id uuid primary key default gen_random_uuid(), organization_id text not null);
      create table posts (
        id serial primary key,
        organization_id text not null,
        author uuid references users(id)     -- single-column FK between tenant tables
      );
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2)); // note, not a failure
    const n = res.notes.find((x) => /foreign key/.test(x.where));
    assert.ok(n, JSON.stringify(res.notes, null, 2));
    assert.match(n.message, /RLS NOT applied/);
    assert.match(n.message, /composite FK/);
    assert.match(n.message, /note rather than a failure/);
  });

  test('does NOT note the tenant FK itself (organization_id -> orgs is the correct pattern)', async () => {
    const { query } = await fresh(`
      create table orgs (organization_id text primary key);
      create table users (id serial primary key, organization_id text not null references orgs(organization_id));
    `);
    const res = await check({ query });
    assert.equal(res.notes.some((n) => /foreign key/.test(n.where)), false, JSON.stringify(res.notes, null, 2));
  });

  test('allowlist: a deliberately global unique key can be exempted', async () => {
    const setup = `
      create table users (id serial primary key, organization_id text not null, slug text not null unique);
    `;
    const flagged = await check({ query: (await fresh(setup)).query });
    assert.equal(flagged.ok, false);
    const okd = await check({ query: (await fresh(setup)).query, config: { allowlist: ['public.users'] } });
    assert.equal(okd.ok, true, JSON.stringify(okd, null, 2));
  });

  test('PROVES the oracle is real: a duplicate insert errors on a row RLS hides', async () => {
    // Not part of the guard (which is catalog-only) — this asserts the premise
    // the guard is built on, so the reasoning can't silently rot.
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table users (id serial primary key, organization_id text not null, email text not null unique);
      grant select, insert on users to authenticated;
      grant usage on all sequences in schema public to authenticated;
      insert into users (organization_id, email) values ('org_B','victim@corp.com');
      alter table users enable row level security;
      create policy tenant on users for all
        using (organization_id = current_setting('app.current_tenant', true))
        with check (organization_id = current_setting('app.current_tenant', true));
    `);
    const Q = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
    await Q('begin');
    await Q('set local role authenticated');
    await Q(`select set_config('app.current_tenant','org_A',true)`);
    const visible = await Q(`select count(*)::int as n from users`);
    assert.equal(visible.rows[0].n, 0); // RLS correctly hides org_B's row
    let code = null;
    try {
      await Q(`insert into users (organization_id, email) values ('org_A','victim@corp.com')`);
    } catch (e) { code = e.code; }
    await Q('rollback');
    // ...and yet the constraint confirms it exists. That's the oracle.
    assert.equal(code, '23505', 'expected a unique_violation revealing the hidden row');
  });
}
