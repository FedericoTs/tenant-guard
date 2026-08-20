/**
 * shadow-tables — tenant data copied somewhere nothing follows it.
 *
 * The verified case: `invoices` has flawless RLS and returns one row to its
 * tenant, while the `audit_log` its trigger writes to returns BOTH tenants'
 * rows — and `rls-proof` reports green, because the destination has no tenant
 * column for it to key on.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/shadow-tables.mjs';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('shadow-tables integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const SOURCE = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select, insert on invoices to authenticated;
  alter table invoices enable row level security;
  create policy tenant on invoices for all
    using (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('CATCHES an audit table a trigger fills with tenant data and nothing protects', async () => {
    const { db, query } = await fresh(`
      ${SOURCE}
      create table audit_log (id serial primary key, actor text, detail text);
      grant select on audit_log to authenticated;
      create function log_invoice() returns trigger language plpgsql security definer as $fn$
        begin
          insert into audit_log (actor, detail) values (current_user, 'invoice ' || new.organization_id);
          return new;
        end $fn$;
      create trigger t_log after insert on invoices for each row execute function log_invoice();
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',999);
    `);

    // Prove the leak first, so this test can't pass on a rotted premise.
    const Q = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
    await Q('begin');
    await Q('set local role authenticated');
    await Q(`select set_config('app.current_tenant','org_A',true)`);
    const src = (await Q(`select count(*)::int n from invoices`)).rows[0].n;
    const shadow = (await Q(`select count(*)::int n from audit_log`)).rows[0].n;
    await Q('rollback');
    assert.equal(src, 1, 'the source table is correctly scoped');
    assert.equal(shadow, 2, 'the shadow shows every tenant');

    // rls-proof is happy; this guard is what catches it.
    assert.equal((await prove({ query })).ok, true);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'public.audit_log');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /written by a trigger on public\.invoices/);
    assert.match(v.message, /no tenant column to scope it by/);
    assert.match(v.fix, /ADD COLUMN organization_id/);
  });

  test('does NOT flag a destination that HAS RLS (the other guards judge that one)', async () => {
    const { query } = await fresh(`
      ${SOURCE}
      create table audit_log (id serial primary key, organization_id text not null, detail text);
      grant select on audit_log to authenticated;
      alter table audit_log enable row level security;
      create policy tenant on audit_log using (organization_id = current_setting('app.current_tenant', true));
      create function log_invoice() returns trigger language plpgsql as $fn$
        begin insert into audit_log (organization_id, detail) values (new.organization_id, 'x'); return new; end $fn$;
      create trigger t_log after insert on invoices for each row execute function log_invoice();
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('does NOT flag a destination the app role cannot read', async () => {
    const { query } = await fresh(`
      ${SOURCE}
      create table audit_log (id serial primary key, detail text);   -- no grant to authenticated
      create function log_invoice() returns trigger language plpgsql security definer as $fn$
        begin insert into audit_log (detail) values ('x'); return new; end $fn$;
      create trigger t_log after insert on invoices for each row execute function log_invoice();
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('flags a destination that HAS a tenant column but no RLS — and says so', async () => {
    const { query } = await fresh(`
      ${SOURCE}
      create table outbox (id serial primary key, organization_id text, payload text);
      grant select on outbox to authenticated;
      create function q_invoice() returns trigger language plpgsql as $fn$
        begin insert into outbox (organization_id, payload) values (new.organization_id, 'x'); return new; end $fn$;
      create trigger t_q after insert on invoices for each row execute function q_invoice();
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => x.where === 'public.outbox');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /despite carrying a "organization_id" column/);
    assert.match(v.fix, /ENABLE ROW LEVEL SECURITY/);
  });

  test('allowlist exempts a destination that is unscoped on purpose', async () => {
    const setup = `
      ${SOURCE}
      create table metrics (id serial primary key, n int);
      grant select on metrics to authenticated;
      create function bump() returns trigger language plpgsql as $fn$
        begin insert into metrics (n) values (1); return new; end $fn$;
      create trigger t_m after insert on invoices for each row execute function bump();
    `;
    assert.equal((await check({ query: (await fresh(setup)).query })).ok, false);
    const okd = await check({ query: (await fresh(setup)).query, config: { allowlist: ['public.metrics'] } });
    assert.equal(okd.ok, true, JSON.stringify(okd, null, 2));
  });

  test('skips cleanly when there are no triggers on tenant tables', async () => {
    const { query } = await fresh(SOURCE);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.match(res.summary, /no triggers on tenant tables/);
  });
}
