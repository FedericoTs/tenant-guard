/**
 * rls-proof end-to-end proof, against a REAL Postgres (embedded via pglite).
 *
 * This is the guard doing the thing no static scanner can: it drops to a
 * non-superuser role, assumes a tenant's identity, and measures whether that
 * session can read another tenant's rows. We assert it PASSES a correctly
 * isolated schema and FAILS three ways a real app leaks: a permissive policy,
 * RLS switched off entirely, and (as a control) confirms single-tenant tables
 * are reported as unproven rather than falsely passed.
 *
 * pglite is a dev-only dependency. If it isn't installed the whole file skips —
 * the pure-logic guarantees still hold via rls-proof.test.mjs, exactly the
 * "a check that doesn't apply skips, it never fails you" philosophy.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('rls-proof integration (pglite not installed — skipped)', { skip: true }, () => {});
}

/** Fresh embedded Postgres + a query adapter shaped like node-postgres. */
async function freshDb(setupSql) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setupSql);
  const query = (text, values) =>
    db.query(text, Array.isArray(values) && values.length ? values : undefined);
  return { db, query };
}

const TENANT_POLICY = `using (organization_id = current_setting('app.current_tenant', true))`;

// A correctly isolated table: RLS on, policy scopes by the tenant column.
const GOOD = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A', 100), ('org_A', 150), ('org_B', 200);
  alter table invoices enable row level security;
  create policy tenant_iso on invoices ${TENANT_POLICY};
`;

if (PGlite) {
  test('PROVES isolation: a correct RLS policy passes the guard', async () => {
    const { query } = await freshDb(GOOD);
    const res = await prove({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.equal(res.scanned, 1);
    assert.match(res.summary, /1\/1 tenant table\(s\) proven isolated/);
  });

  test('CATCHES a permissive policy: USING (true) leaks -> guard fails', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to authenticated;
      insert into invoices (organization_id, amount) values ('org_A', 100), ('org_B', 200);
      alter table invoices enable row level security;
      create policy leaky on invoices using (true);
    `);
    const res = await prove({ query });
    assert.equal(res.ok, false);
    assert.equal(res.violations.length, 1);
    assert.match(res.violations[0].where, /invoices \(organization_id\)/);
    assert.match(res.violations[0].message, /permissive or missing the tenant predicate/);
    assert.equal(res.violations[0].rlsEnabled, true);
  });

  test('CATCHES RLS switched off entirely: the CVE-2025-48757 case -> guard fails', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to authenticated;
      insert into invoices (organization_id, amount) values ('org_A', 100), ('org_B', 200);
      -- NOTE: row level security never enabled -> authenticated sees everything
    `);
    const res = await prove({ query });
    assert.equal(res.ok, false);
    assert.equal(res.violations.length, 1);
    assert.match(res.violations[0].message, /ROW LEVEL SECURITY is not enabled/);
    assert.equal(res.violations[0].rlsEnabled, false);
    assert.match(res.violations[0].fix, /ENABLE ROW LEVEL SECURITY/);
  });

  test('does NOT falsely pass a single-tenant table: reported as not proven', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to authenticated;
      insert into invoices (organization_id, amount) values ('org_A', 100);
      alter table invoices enable row level security;
      create policy tenant_iso on invoices ${TENANT_POLICY};
    `);
    const res = await prove({ query });
    assert.equal(res.ok, true); // no leak, but...
    assert.equal(res.violations.length, 0);
    assert.ok(res.notes.some((n) => /cannot prove cross-tenant isolation/.test(n.message)));
    assert.match(res.summary, /not proven/);
  });

  test('mixed schema: isolates the good table, flags the leaky one', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null);
      create table audit_log (id serial primary key, tenant_id text not null);
      grant select on invoices, audit_log to authenticated;
      insert into invoices (organization_id) values ('org_A'), ('org_B');
      insert into audit_log (tenant_id) values ('org_A'), ('org_B');
      alter table invoices enable row level security;
      create policy good on invoices ${TENANT_POLICY};
      alter table audit_log enable row level security;
      create policy bad on audit_log using (true);
    `);
    const res = await prove({ query });
    assert.equal(res.ok, false);
    assert.equal(res.violations.length, 1);
    assert.match(res.violations[0].where, /audit_log \(tenant_id\)/);
    assert.equal(res.scanned, 2);
  });

  test('a table the app role cannot read at all is reported safe (no-access), not a leak or a pass', async () => {
    const { query } = await freshDb(`
      create table secrets (id serial primary key, organization_id text not null);
      -- deliberately NO grant to authenticated
      insert into secrets (organization_id) values ('org_A'), ('org_B');
      alter table secrets enable row level security;
    `);
    const res = await prove({ query });
    assert.equal(res.ok, true); // can't read it -> can't leak it
    assert.equal(res.violations.length, 0);
    assert.ok(res.notes.some((n) => /cannot read this table at all/.test(n.message)));
    assert.match(res.summary, /0\/1 tenant table\(s\) proven isolated/); // NOT counted as proven
  });

  test('non-destructive: after the proof the connection is rolled back to full visibility', async () => {
    const { db, query } = await freshDb(GOOD);
    await prove({ query });
    // Back as the privileged connecting role, RLS bypassed: both tenants visible again,
    // and the transaction-local SET ROLE is gone.
    const all = await db.query(`select count(*)::int as n from invoices`);
    assert.equal(all.rows[0].n, 3);
    const who = await db.query(`select current_setting('app.current_tenant', true) as t`);
    assert.equal(who.rows[0].t ?? '', ''); // GUC did not leak out of the rolled-back txn
  });
}
