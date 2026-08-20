/**
 * SECURITY DEFINER RPCs (threat-model 4.3) against a real Postgres.
 *
 * The headline case: `invoices` has flawless RLS, and a definer function hands
 * the whole table out anyway — because it runs as its owner and PostgREST
 * exposes it at /rest/v1/rpc/<name>. `rls-proof` passes on that database; this
 * guard is what catches it.
 *
 * The safety rule is tested too: a VOLATILE definer function is NEVER called,
 * because an unknown body can commit autonomously. Postgres itself enforces that
 * a STABLE function cannot write, which is what makes calling those safe.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/definer-rpc.mjs';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('definer-rpc integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const SECURED = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200),('org_B',300);
  alter table invoices enable row level security;
  create policy tenant on invoices
    using (organization_id = current_setting('app.current_tenant', true));
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('CATCHES an RPC that trusts a caller-supplied tenant id', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function get_invoices(org text) returns setof invoices
        language sql security definer stable as $$ select * from invoices where organization_id = org $$;
      grant execute on function get_invoices(text) to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'trusts-argument');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.where, /get_invoices/);
    assert.match(v.message, /ANOTHER TENANT'S id/);
    assert.match(v.message, /rpc\/get_invoices/);
    assert.match(v.fix, /never from an argument/);
  });

  test('the TABLE proves isolated on that same database — which is the whole point', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function get_invoices(org text) returns setof invoices
        language sql security definer stable as $$ select * from invoices where organization_id = org $$;
      grant execute on function get_invoices(text) to authenticated;
    `);
    assert.equal((await prove({ query })).ok, true);          // policies are perfect...
    assert.equal((await check({ query })).ok, false);          // ...and routed around
  });

  test('CATCHES a zero-arg RPC that never filters by tenant at all', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function all_invoices() returns setof invoices
        language sql security definer stable as $$ select * from invoices $$;
      grant execute on function all_invoices() to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'no-filter');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /runs as its owner/);
  });

  test('names the arg-ignoring case correctly (control arm: rows even for a tenant that cannot exist)', async () => {
    const { query } = await fresh(`
      ${SECURED}
      -- takes an org but ignores it: the control arm must reclassify this as no-filter
      create function sloppy(org text) returns setof invoices
        language sql security definer stable as $$ select * from invoices $$;
      grant execute on function sloppy(text) to authenticated;
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => x.where.includes('sloppy'));
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.kind, 'no-filter');
    assert.match(v.message, /isn't filtering by tenant at all/);
  });

  test('does NOT flag an RPC that re-filters from the session', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function my_invoices() returns setof invoices
        language sql security definer stable as $$
          select * from invoices where organization_id = current_setting('app.current_tenant', true) $$;
      grant execute on function my_invoices() to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /proven tenant-scoped/);
  });

  test('does NOT flag a definer function the app role cannot EXECUTE', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function admin_all() returns setof invoices
        language sql security definer stable as $$ select * from invoices $$;
      revoke execute on function admin_all() from public;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('NEVER calls a VOLATILE function — reports it as unproven, and says why', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function volatile_all() returns setof invoices
        language sql security definer volatile as $$ select * from invoices $$;
      grant execute on function volatile_all() to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2)); // a note, never a failure
    const n = res.notes.find((x) => /volatile_all/.test(x.where));
    assert.ok(n, JSON.stringify(res.notes, null, 2));
    assert.match(n.message, /NOT PROVEN/);
    assert.match(n.message, /commit autonomously/);
    assert.match(n.message, /mark it STABLE/);
  });

  test('skips a multi-argument RPC rather than inventing values, and says so', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function search(org text, q text, lim int) returns setof invoices
        language sql security definer stable as $$ select * from invoices where organization_id = org limit lim $$;
      grant execute on function search(text, text, int) to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.ok(res.notes.some((n) => /search/.test(n.where) && /won't invent values/.test(n.message)), JSON.stringify(res.notes, null, 2));
  });

  test('skips cleanly when there are no SECURITY DEFINER functions', async () => {
    const { query } = await fresh(SECURED);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.equal(res.skipped, true);
    assert.match(res.summary, /no definer functions/);
  });
}
