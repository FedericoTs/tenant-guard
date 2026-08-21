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
    const n = res.notes.find((x) => /volatile_all/.test(x.where) && /NOT PROVEN/.test(x.message));
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

// ── SQL injection inside a definer function (0.17.0) ─────────────────

if (PGlite) {
  test('CATCHES SQL injection in a definer function — and the injection really works', async () => {
    const { db, query } = await fresh(`
      ${SECURED}
      create function search_notes(q text) returns setof invoices
        language plpgsql security definer as $fn$
        begin
          return query execute 'select * from invoices where organization_id = current_setting(''app.current_tenant'', true) and amount::text like ''%' || q || '%''';
        end $fn$;
      grant execute on function search_notes(text) to authenticated;
    `);
    // First: prove the exploit, so this test can't pass on a rotted premise.
    const Q = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
    await Q('begin');
    await Q('set local role authenticated');
    await Q(`select set_config('app.current_tenant','org_A',true)`);
    const scoped = (await Q(`select count(*)::int n from invoices`)).rows[0].n;
    const injected = (await Q(`select count(*)::int n from search_notes($1)`, ["%' or true --"])).rows[0].n;
    await Q('rollback');
    assert.equal(scoped, 1, 'RLS itself is correct: org_A sees one row');
    assert.ok(injected > scoped, `injection should bypass RLS (saw ${injected} vs ${scoped})`);

    // Then: the guard catches it, from the body — no execution needed.
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'sql-injection');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /concatenated straight into/);
    assert.match(v.message, /bypasses RLS entirely/);
    assert.match(v.fix, /USING/);
  });

  test('flags format() with %s (which escapes nothing), not %L or %I', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function bad_fmt(q text) returns setof invoices
        language plpgsql security definer as $fn$
        begin return query execute format('select * from invoices where note = %s', q); end $fn$;
      create function good_fmt(q text) returns setof invoices
        language plpgsql security definer as $fn$
        begin return query execute format('select * from invoices where note = %L', q); end $fn$;
      grant execute on function bad_fmt(text), good_fmt(text) to authenticated;
    `);
    const res = await check({ query });
    const inj = res.violations.filter((x) => x.kind === 'sql-injection');
    assert.equal(inj.length, 1, JSON.stringify(inj, null, 2));
    assert.match(inj[0].where, /bad_fmt/);   // %s does no escaping
    assert.doesNotMatch(inj[0].where, /good_fmt/); // %L is correct
  });

  test('does NOT flag EXECUTE ... USING, or quote_literal — those are the correct forms', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function bound(q text) returns setof invoices
        language plpgsql security definer as $fn$
        begin return query execute 'select * from invoices where note = $1' using q; end $fn$;
      create function quoted(q text) returns setof invoices
        language plpgsql security definer as $fn$
        begin return query execute 'select * from invoices where note = ' || quote_literal(q); end $fn$;
      grant execute on function bound(text), quoted(text) to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'sql-injection'), false, JSON.stringify(res.violations, null, 2));
  });

  test('flags an unpinned search_path ONLY when the role can actually create objects', async () => {
    const withCreate = await fresh(`
      ${SECURED}
      grant create on schema public to authenticated;   -- somewhere to plant a shadow
      create function helper() returns setof invoices
        language sql security definer stable as $$ select * from invoices $$;
      grant execute on function helper() to authenticated;
    `);
    const flagged = await check({ query: withCreate.query });
    const sp = flagged.violations.find((x) => x.kind === 'search-path');
    assert.ok(sp, JSON.stringify(flagged.violations, null, 2));
    assert.match(sp.message, /resolve through the CALLER's search_path/);
    assert.match(sp.fix, /SET search_path/);

    const noCreate = await fresh(`
      ${SECURED}
      create function helper() returns setof invoices
        language sql security definer stable as $$ select * from invoices $$;
      grant execute on function helper() to authenticated;
    `);
    const res = await check({ query: noCreate.query });
    // Nowhere to plant a shadowing object => a note, not a build failure.
    assert.equal(res.violations.some((x) => x.kind === 'search-path'), false, JSON.stringify(res.violations, null, 2));
    assert.ok(res.notes.some((n) => /Not exploitable here/.test(n.message)));
  });

  test('does NOT flag a function whose search_path is pinned COMPLETELY (pg_temp named)', async () => {
    const { query } = await fresh(`
      ${SECURED}
      grant create on schema public to authenticated;
      create function helper() returns setof invoices
        language sql security definer stable
        set search_path = pg_catalog, public, pg_temp
        as $$ select * from invoices where organization_id = current_setting('app.current_tenant', true) $$;
      grant execute on function helper() to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'search-path'), false, JSON.stringify(res.violations, null, 2));
  });
}
