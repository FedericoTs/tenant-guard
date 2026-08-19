/**
 * Partitioned tenant tables — a structural blind spot that made the flagship
 * guard report GREEN on a leaking database.
 *
 * Two compounding causes, both fixed here:
 *   1. A partitioned parent is `relkind = 'p'`, and the introspection only looked
 *      at `'r'` — so the parent was never scanned at all.
 *   2. List-partitioning by tenant means every partition holds exactly ONE tenant
 *      by construction, so the two-tenant probe could never fire and every
 *      partition was written off as "only 1 tenant — cannot prove".
 *
 * Net effect before the fix: `ok: true` on a database where any authenticated
 * user reads every other tenant by naming the partition directly. PostgREST
 * exposes each partition as its own endpoint, so this is reachable, not theoretical.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('partition integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

const TENANT_POLICY = `using (organization_id = current_setting('app.current_tenant', true))`;

if (PGlite) {
  test('CATCHES a partition readable directly, even though the PARENT is correctly scoped', async () => {
    const { query } = await fresh(`
      create table events (id serial, organization_id text not null, body text)
        partition by list (organization_id);
      create table events_a partition of events for values in ('org_A');
      create table events_b partition of events for values in ('org_B');
      grant select on events, events_a, events_b to authenticated;
      insert into events (organization_id, body) values ('org_A','a1'),('org_B','b1'),('org_B','b2');
      -- RLS on the PARENT only — the idiomatic (and insufficient) setup.
      alter table events enable row level security;
      create policy tenant on events ${TENANT_POLICY};
    `);
    const res = await prove({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const b = res.violations.find((v) => v.where.startsWith('public.events_b'));
    assert.ok(b, JSON.stringify(res.violations, null, 2));
    assert.match(b.message, /PARTITION/);
    assert.match(b.message, /DIRECTLY/);
    assert.match(b.message, /read 2 of its row\(s\)/); // org_B's two rows
    assert.match(b.fix, /ENABLE ROW LEVEL SECURITY/);
    // and the parent itself is fine — the finding is precisely located
    assert.equal(res.violations.some((v) => v.where.startsWith('public.events (')), false);
  });

  test('PROVES a correctly-secured partitioned table (RLS on every partition too)', async () => {
    const { query } = await fresh(`
      create table events (id serial, organization_id text not null, body text)
        partition by list (organization_id);
      create table events_a partition of events for values in ('org_A');
      create table events_b partition of events for values in ('org_B');
      grant select on events, events_a, events_b to authenticated;
      insert into events (organization_id, body) values ('org_A','a1'),('org_B','b1');
      alter table events   enable row level security;
      alter table events_a enable row level security;
      alter table events_b enable row level security;
      create policy tenant   on events   ${TENANT_POLICY};
      create policy tenant_a on events_a ${TENANT_POLICY};
      create policy tenant_b on events_b ${TENANT_POLICY};
    `);
    const res = await prove({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('the partitioned PARENT is scanned at all (relkind = p was previously skipped)', async () => {
    const { query } = await fresh(`
      create table events (id serial, organization_id text not null)
        partition by list (organization_id);
      create table events_a partition of events for values in ('org_A');
      create table events_b partition of events for values in ('org_B');
      grant select on events, events_a, events_b to authenticated;
      insert into events (organization_id) values ('org_A'),('org_B');
      -- no RLS anywhere: the parent must be reported, not silently skipped
      alter table events_a enable row level security;
      alter table events_b enable row level security;
      create policy a on events_a ${TENANT_POLICY};
      create policy b on events_b ${TENANT_POLICY};
    `);
    const res = await prove({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(res.violations.some((v) => v.where.startsWith('public.events (')), JSON.stringify(res.violations, null, 2));
  });

  // The same machinery upgrades ordinary single-tenant tables from
  // "cannot prove" to a real verdict, by impersonating a tenant from elsewhere.
  test('a SINGLE-tenant table is now provable by impersonating a tenant from elsewhere', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null);
      create table audit_log (id serial primary key, organization_id text not null, msg text);
      grant select on invoices, audit_log to authenticated;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      insert into audit_log (organization_id, msg) values ('org_A','only tenant A here');
      alter table invoices enable row level security;
      alter table audit_log enable row level security;
      create policy ok on invoices ${TENANT_POLICY};
      create policy oops on audit_log using (true);   -- wide open, but only ONE tenant present
    `);
    const res = await prove({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where.startsWith('public.audit_log'));
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /acting as a different tenant read 1 row\(s\)/);
  });

  test('still reports "cannot prove" when the database knows only ONE tenant in total', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A');
      alter table invoices enable row level security;
      create policy oops on invoices using (true);
    `);
    const res = await prove({ query });
    // No foreign tenant exists anywhere to impersonate, so nothing is proven —
    // and, correctly, nothing is claimed either.
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.ok(res.notes.some((n) => /cannot prove cross-tenant isolation/.test(n.message)), JSON.stringify(res.notes, null, 2));
  });
}
