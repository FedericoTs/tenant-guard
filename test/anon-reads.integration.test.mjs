/**
 * anon-reads end-to-end against a REAL Postgres (embedded via pglite).
 *
 * The CVE-2025-48757 class: the anonymous role reading a table that holds tenants'
 * data. It FLAGS both the RLS-off grant and an RLS-on policy that lets anon read;
 * it does NOT flag a table scoped to `authenticated`, nor a public table with no
 * tenant column (which it never scans).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/anon-reads.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('anon-reads integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role anon nologin;`);
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('FLAGS a tenant table anon can read with RLS OFF (the CVE class, structural)', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to anon;
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
      -- NOTE: RLS never enabled -> anon reads every tenant's rows
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'public.invoices');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /RLS is OFF/);
  });

  test('FLAGS a tenant table anon can read under RLS (a permissive policy, proven by probe)', async () => {
    const { query } = await fresh(`
      create table documents (id serial primary key, organization_id text not null, body text);
      grant select on documents to anon;
      insert into documents (organization_id, body) values ('org_A','x'),('org_B','y');
      alter table documents enable row level security;
      create policy pub on documents for select to anon using (true);   -- BUG: anon reads all tenants
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'public.documents');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /a policy permits it/);
  });

  test('does NOT flag a tenant table scoped to authenticated (anon reads nothing)', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;   -- anon has NO grant
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy tenant on invoices for select to authenticated using (true);
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('does NOT false-flag the safe TO public idiom (anon reads 0 rows — the FP a catalog scan gets wrong)', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to anon;            -- anon HAS the grant (default in Supabase)...
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
      alter table invoices enable row level security;
      -- policy applies TO public (which includes anon), but its USING evaluates FALSE for an
      -- unauthenticated caller: current_setting is unset -> organization_id = NULL -> no rows.
      create policy tenant on invoices for select to public
        using (organization_id = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2)); // probing as anon proves it's safe; a catalog-only check would cry wolf
    assert.equal(res.violations.length, 0);
  });

  test('does NOT scan a public table with no tenant column (only tenant tables are checked)', async () => {
    const { query } = await fresh(`
      create table blog_posts (id serial primary key, slug text, body text);   -- no tenant column
      grant select on blog_posts to anon;
      insert into blog_posts (slug, body) values ('hello','world');
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2)); // blog_posts is public content, never a tenant table
    assert.match(res.summary, /skipped|none readable/);
  });

  test('FLAGS a MATERIALIZED VIEW anon can read — this CVE class at its worst, invisible to a table-only scan', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to authenticated;      -- base table is locked down for anon
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
      alter table invoices enable row level security;
      create policy tenant on invoices for select to authenticated using (true);
      -- ...but the dashboard matview beside it is granted to anon, and RLS can
      -- never apply to a materialized view.
      create materialized view invoice_totals as
        select organization_id, sum(amount)::int as amount from invoices group by organization_id;
      grant select on invoice_totals to anon;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'public.invoice_totals');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.kind, 'matview');
    assert.match(v.message, /MATERIALIZED VIEW/);
    assert.match(v.fix, /CANNOT be scoped by RLS/i);
    // the base table itself is NOT flagged — anon has no grant on it
    assert.equal(res.violations.some((x) => x.where === 'public.invoices'), false);
  });

  test('does NOT false-flag a security_invoker VIEW over an RLS table (views are probed, never judged structurally)', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to anon;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      -- anon-scoped policy that evaluates false for an unauthenticated caller
      create policy tenant on invoices for select to public
        using (organization_id = current_setting('app.current_tenant', true));
      create view invoice_v with (security_invoker = true) as select id, organization_id from invoices;
      grant select on invoice_v to anon;
    `);
    const res = await check({ query });
    // A view's relrowsecurity is always false — judging it structurally would
    // false-flag this safe view. The probe returns 0 rows, so it passes.
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('allowlist: a deliberately-public tenant table can be exempted', async () => {
    const { query } = await fresh(`
      create table price_book (id serial primary key, organization_id text not null, sku text);
      grant select on price_book to anon;
      insert into price_book (organization_id, sku) values ('org_A','A1');
    `);
    const flagged = await check({ query });
    assert.equal(flagged.ok, false); // flagged by default
    const okd = await check({ query, config: { allowlist: ['public.price_book'] } });
    assert.equal(okd.ok, true, JSON.stringify(okd, null, 2));
  });
}
