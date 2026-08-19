/**
 * view-isolation end-to-end against a REAL Postgres (embedded via pglite).
 *
 * The tests that carry the design: a VIEW without security_invoker over a
 * perfectly-RLS'd table hands out every tenant (because it runs as its owner); a
 * MATERIALIZED VIEW does the same and cannot be fixed with a policy at all; and a
 * view WITH security_invoker over the same table is proven isolated — no false
 * positive. Plus: the base table alone looks clean, which is exactly why a
 * table-only checker misses this class.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/view-isolation.mjs';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('view-isolation integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

// A properly-secured tenant table: RLS on, policy scopes by the tenant column.
const SECURE_TABLE = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A',100),('org_A',150),('org_B',200);
  alter table invoices enable row level security;
  create policy tenant_iso on invoices
    using (organization_id = current_setting('app.current_tenant', true));
`;

if (PGlite) {
  test('CATCHES a VIEW without security_invoker: it runs as its OWNER, handing out every tenant', async () => {
    const { query } = await fresh(`
      ${SECURE_TABLE}
      -- The classic footgun: a convenience view over a correctly-RLS'd table.
      -- It is owned by the privileged role, so the base RLS is evaluated as the
      -- OWNER, not the caller -> every tenant's rows come back.
      create view invoice_summary as select id, organization_id, amount from invoices;
      grant select on invoice_summary to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where.startsWith('public.invoice_summary'));
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /does not set security_invoker/);
    assert.match(v.message, /OWNER/);
    assert.match(v.fix, /ALTER VIEW .* SET \(security_invoker = true\)/);
  });

  test('the BASE TABLE alone looks perfectly isolated — which is why a table-only check misses this', async () => {
    const { query } = await fresh(`
      ${SECURE_TABLE}
      create view invoice_summary as select id, organization_id, amount from invoices;
      grant select on invoice_summary to authenticated;
    `);
    // rls-proof introspects base tables (relkind='r') and is perfectly happy...
    const tableRes = await prove({ query });
    assert.equal(tableRes.ok, true, JSON.stringify(tableRes, null, 2));
    // ...while the view beside it leaks every tenant.
    const viewRes = await check({ query });
    assert.equal(viewRes.ok, false, JSON.stringify(viewRes, null, 2));
  });

  test('CATCHES a MATERIALIZED VIEW: RLS never applies to it, and no policy can fix it', async () => {
    const { query } = await fresh(`
      ${SECURE_TABLE}
      create materialized view invoice_totals as
        select organization_id, sum(amount)::int as amount from invoices group by organization_id;
      grant select on invoice_totals to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where.startsWith('public.invoice_totals'));
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.kind, 'matview');
    assert.match(v.message, /MATERIALIZED VIEW/);
    assert.match(v.message, /NEVER applies/i);
    assert.match(v.fix, /CANNOT be scoped by RLS/i);
    assert.match(v.fix, /REVOKE SELECT/);
    assert.doesNotMatch(v.fix, /ALTER VIEW/); // security_invoker is NOT the fix for a matview
  });

  test('PROVES isolation for a view WITH security_invoker (no false positive)', async () => {
    const { query } = await fresh(`
      ${SECURE_TABLE}
      create view invoice_summary with (security_invoker = true) as
        select id, organization_id, amount from invoices;
      grant select on invoice_summary to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.match(res.summary, /1\/1 tenant view\(s\) proven isolated/);
  });

  test('a security_invoker view over a LEAKY table blames the table, not the view', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to authenticated;
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
      alter table invoices enable row level security;
      create policy oops on invoices using (true);   -- the real bug is here
      create view invoice_summary with (security_invoker = true) as
        select id, organization_id, amount from invoices;
      grant select on invoice_summary to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where.startsWith('public.invoice_summary'));
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /IS security_invoker/);
    assert.match(v.message, /leak is in the underlying table/i);
    assert.match(v.fix, /tenant-guard prove/); // points at the right tool for the real fix
  });

  test('does NOT flag a view the app role cannot read (no grant — nothing exposed)', async () => {
    const { query } = await fresh(`
      ${SECURE_TABLE}
      create view invoice_summary as select id, organization_id, amount from invoices;
      -- deliberately NO grant to authenticated
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('does NOT scan a view with no tenant column (public content is never flagged)', async () => {
    const { query } = await fresh(`
      create table posts (id serial primary key, slug text, body text);
      grant select on posts to authenticated;
      insert into posts (slug, body) values ('hello','world');
      create view published as select id, slug from posts;
      grant select on published to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /skipped — no tenant views/);
  });

  test('allowlist: a deliberately cross-tenant view can be exempted', async () => {
    const { query } = await fresh(`
      ${SECURE_TABLE}
      create view invoice_summary as select id, organization_id, amount from invoices;
      grant select on invoice_summary to authenticated;
    `);
    const flagged = await check({ query });
    assert.equal(flagged.ok, false);
    const okd = await check({ query, config: { allowlist: ['public.invoice_summary'] } });
    assert.equal(okd.ok, true, JSON.stringify(okd, null, 2));
  });

  test('claim shortcut works here too (JWT-claim policies, no JWT secret in CI)', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy p on invoices using (organization_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id'));
      create view invoice_v with (security_invoker = true) as select id, organization_id from invoices;
      grant select on invoice_v to authenticated;
    `);
    const res = await check({ query, config: { claim: 'org_id' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });
}
