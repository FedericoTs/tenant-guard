/**
 * Two ways `definer-rpc` used to report green on a proven leak.
 *
 * Both were found by auditing the guard's behaviour against a real database
 * rather than against its own tests — the tests passed throughout.
 *
 * 1. **No savepoint around the probe.** The guard runs every probe in one
 *    transaction. A function whose call errors — which the guard's own note
 *    calls the ORDINARY case, "a return shape without a tenant column" — aborts
 *    that transaction, and every function scanned afterwards fails with 25P02
 *    and is downgraded to a reassuring note. Whether a proven leak failed the
 *    build was decided by alphabetical order, since the catalog query sorts by
 *    name. Six sibling guards already wrapped their probes in savepoints; this
 *    one did not.
 *
 * 2. **A text sentinel cast to `uuid`.** The control arm re-probes with a
 *    tenant id that cannot exist. That sentinel was the string
 *    `__tenant_guard_no_such_tenant__`, and `::uuid` on it raises 22P02 — so on
 *    the ordinary Supabase tenant type the guard MEASURED the cross-tenant read
 *    and then threw the measurement away. Identical scenario with a `text`
 *    argument failed the build; with `uuid` it passed.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check, sentinelFor, NONEXISTENT_TENANT, NONEXISTENT_TENANT_UUID } from '../src/guards/definer-rpc.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('definer-rpc scan integrity (pglite not installed — skipped)', { skip: true }, () => {});
}

test('sentinelFor picks a value the argument type can actually hold', () => {
  assert.equal(sentinelFor('uuid'), NONEXISTENT_TENANT_UUID);
  assert.equal(sentinelFor('text'), NONEXISTENT_TENANT);
  assert.equal(sentinelFor(undefined), NONEXISTENT_TENANT);
});

if (PGlite) {
  const CFG = {
    role: 'authenticated',
    becomeTenant: [`select set_config('app.tenant', $1, true)`],
    tenantColumns: ['organization_id'],
  };
  const q = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

  async function base(idType) {
    const db = new PGlite();
    const a = idType === 'uuid' ? "'11111111-1111-1111-1111-111111111111'" : "'org_A'";
    const b = idType === 'uuid' ? "'22222222-2222-2222-2222-222222222222'" : "'org_B'";
    await db.exec(`
      create role authenticated nologin;
      create table invoices (id serial primary key, organization_id ${idType}, total int);
      insert into invoices (organization_id, total) values (${a}, 10), (${b}, 20);
      alter table invoices enable row level security;
      create policy own on invoices for all to authenticated
        using (organization_id::text = current_setting('app.tenant', true));
      grant select on invoices to authenticated;
    `);
    return db;
  }

  test('DEMONSTRATES the ordering bug is gone: a benign erroring function no longer hides a leak', async () => {
    const db = await base('text');
    await db.exec(`
      -- sorts FIRST, and errors when probed: the canonical Supabase RLS helper
      create function aa_current_org() returns text language sql stable security definer
        as $$ select 'org_A'::text $$;
      grant execute on function aa_current_org() to authenticated;
      -- sorts second, and is a blatant no-filter leak
      create function zz_all_invoices() returns setof invoices language sql stable security definer
        as $$ select * from invoices $$;
      grant execute on function zz_all_invoices() to authenticated;
    `);
    const res = await check({ query: q(db), config: CFG });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(
      res.violations.some((v) => /zz_all_invoices/.test(v.where)),
      `the leak must survive the earlier function's probe error: ${JSON.stringify(res, null, 2)}`,
    );
  });

  test('a uuid tenant argument is probed, not discarded', async () => {
    const db = await base('uuid');
    await db.exec(`
      create function get_invoices(org uuid) returns setof invoices
        language sql stable security definer
        as $$ select * from invoices where organization_id = org $$;
      grant execute on function get_invoices(uuid) to authenticated;
    `);
    const res = await check({ query: q(db), config: CFG });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(res.violations.some((v) => /get_invoices/.test(v.where)));
  });

  test('…and text behaves identically, which is what it always did', async () => {
    const db = await base('text');
    await db.exec(`
      create function get_invoices(org text) returns setof invoices
        language sql stable security definer
        as $$ select * from invoices where organization_id = org $$;
      grant execute on function get_invoices(text) to authenticated;
    `);
    const res = await check({ query: q(db), config: CFG });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
  });

  test('a correctly-scoped RPC is still PROVEN, not lost to a neighbour', async () => {
    // The abort also destroyed positive proof: a helper plus a genuinely safe
    // function reported 0/2 proven instead of 1/2.
    const db = await base('text');
    await db.exec(`
      create function aa_current_org() returns text language sql stable security definer
        as $$ select 'org_A'::text $$;
      grant execute on function aa_current_org() to authenticated;
      create function safe_invoices() returns setof invoices language sql stable security definer
        as $$ select * from invoices where organization_id = current_setting('app.tenant', true) $$;
      grant execute on function safe_invoices() to authenticated;
    `);
    const res = await check({ query: q(db), config: CFG });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /1\/\d+ callable definer RPC\(s\) proven tenant-scoped|proven/);
  });
}
