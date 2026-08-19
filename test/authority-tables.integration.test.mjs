/**
 * Threat-model 2.10 — the policy's AUTHORITY is user-writable.
 *
 * `USING (org_id IN (SELECT org_id FROM memberships WHERE user_id = auth.uid()))`
 * is the textbook-correct multi-tenant policy. It is also completely bypassable
 * if the user can write `memberships`: insert yourself a row for someone else's
 * org and every policy that trusts the table now returns their data — legitimately.
 *
 * The protected table's policy is flawless in all of these. The soft thing is one
 * table away, which is exactly why per-table checking never finds it. The
 * dependency is read from `pg_depend`, so it's exact rather than a regex guess.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/identity-trust.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('authority-table integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

// The protected table + a correct policy that derives authority from memberships.
const PROTECTED = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
  alter table invoices enable row level security;
  create policy tenant on invoices using (
    organization_id in (
      select m.organization_id from memberships m
      where m.user_id = (current_setting('app.uid', true))::uuid
    )
  );
`;

if (PGlite) {
  test('FLAGS a membership table with RLS OFF that policies derive authority from', async () => {
    const { query } = await fresh(`
      create table memberships (user_id uuid not null, organization_id text not null);
      grant select, insert on memberships to authenticated;   -- no RLS at all
      ${PROTECTED}
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'writable-authority');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.where, 'public.memberships');
    assert.match(v.message, /RLS is OFF/);
    assert.match(v.message, /membership of ANY tenant/);
    assert.match(v.message, /public\.invoices/); // names what depends on it
    assert.match(v.fix, /no_self_grant/);
  });

  test('FLAGS the near-miss: WITH CHECK pins WHO you are but never WHICH tenant', async () => {
    const { query } = await fresh(`
      create table memberships (user_id uuid not null, organization_id text not null);
      grant select, insert on memberships to authenticated;
      alter table memberships enable row level security;
      -- Looks careful, and is the most common real-world shape. It constrains
      -- user_id and says nothing at all about organization_id, so a user can
      -- insert themselves into any org they like.
      create policy self on memberships for insert
        with check (user_id = (current_setting('app.uid', true))::uuid);
      ${PROTECTED}
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'writable-authority');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /never constrains "organization_id"/);
    assert.match(v.message, /pins WHO you are but leaves WHICH TENANT wide open/);
  });

  test('does NOT flag a membership table whose INSERT check constrains the tenant column', async () => {
    const { query } = await fresh(`
      create table memberships (user_id uuid not null, organization_id text not null);
      grant select, insert on memberships to authenticated;
      alter table memberships enable row level security;
      create policy scoped on memberships for insert
        with check (
          user_id = (current_setting('app.uid', true))::uuid
          and organization_id = current_setting('app.current_tenant', true)
        );
      ${PROTECTED}
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'writable-authority'), false, JSON.stringify(res.violations, null, 2));
  });

  test('does NOT flag a membership table with RLS on and NO write policy (writes are denied)', async () => {
    const { query } = await fresh(`
      create table memberships (user_id uuid not null, organization_id text not null);
      grant select, insert on memberships to authenticated;
      alter table memberships enable row level security;
      create policy read_own on memberships for select
        using (user_id = (current_setting('app.uid', true))::uuid);   -- reads only
      ${PROTECTED}
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'writable-authority'), false, JSON.stringify(res.violations, null, 2));
  });

  test('does NOT flag a membership table the role cannot write at all (no grant)', async () => {
    const { query } = await fresh(`
      create table memberships (user_id uuid not null, organization_id text not null);
      grant select on memberships to authenticated;   -- read-only: no self-grant possible
      ${PROTECTED}
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'writable-authority'), false, JSON.stringify(res.violations, null, 2));
  });

  test('catches the UPDATE shape too — re-pointing your own membership row at another tenant', async () => {
    const { query } = await fresh(`
      create table memberships (user_id uuid not null, organization_id text not null);
      grant select, update on memberships to authenticated;
      alter table memberships enable row level security;
      create policy own on memberships for update
        using (user_id = (current_setting('app.uid', true))::uuid)
        with check (user_id = (current_setting('app.uid', true))::uuid);   -- org unconstrained
      ${PROTECTED}
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => x.kind === 'writable-authority');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /UPDATE/);
  });

  test('reports UNKNOWN (a note, not a failure) when the authority table has no tenant column', async () => {
    const { query } = await fresh(`
      create table admin_flags (user_id uuid not null, is_admin boolean not null default false);
      grant select, insert on admin_flags to authenticated;
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A');
      alter table invoices enable row level security;
      create policy tenant on invoices using (
        exists (select 1 from admin_flags f where f.user_id = (current_setting('app.uid', true))::uuid and f.is_admin)
      );
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'writable-authority'), false);
    assert.ok(res.notes.some((n) => n.where === 'public.admin_flags' && /no recognised tenant column/.test(n.message)), JSON.stringify(res.notes, null, 2));
  });
}
