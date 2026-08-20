/**
 * role-capabilities — what the app role can reach that isn't a table.
 *
 * The severity split is the point, and it is tested both ways: a capability that
 * BYPASSES RLS (dblink opens a new connection as another role; file reads never
 * touch the policy layer) fails the build, while outbound-HTTP capability is a
 * note — real, but exfiltration rather than a cross-tenant read, and this tool
 * does not fail builds on findings it can't stand behind as tenant isolation.
 *
 * The real extensions aren't available in an embedded Postgres, so these stand in
 * functions with the same names — which is exactly what the guard matches on.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/role-capabilities.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('role-capabilities integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('FAILS when the app role can EXECUTE dblink — it opens a connection RLS knows nothing about', async () => {
    const { query } = await fresh(`
      create function dblink(text, text) returns setof record language sql as $$ select 1, 'x' $$;
      grant execute on function dblink(text, text) to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'rls-bypass');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /NEW database connection/);
    assert.match(v.message, /read every tenant/);
    assert.match(v.fix, /REVOKE EXECUTE/);
    assert.match(v.fix, /PUBLIC/); // revoking from the role alone is a no-op
  });

  test('FAILS on a file-read capability — it never touches the policy layer', async () => {
    const { query } = await fresh(`
      create function pg_read_file(text) returns text language sql as $$ select 'x' $$;
      grant execute on function pg_read_file(text) to authenticated;
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => x.kind === 'rls-bypass');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /outside the policy layer/);
  });

  test('outbound HTTP is a NOTE, not a failure — exfiltration, not a cross-tenant read', async () => {
    const { query } = await fresh(`
      create function http_post(text, text) returns int language sql as $$ select 200 $$;
      grant execute on function http_post(text, text) to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2)); // never a build failure
    const n = res.notes.find((x) => /http_post/.test(x.where));
    assert.ok(n, JSON.stringify(res.notes, null, 2));
    assert.match(n.message, /outbound HTTP/);
    assert.match(n.message, /not a cross-tenant READ/);
    assert.match(n.message, /still worth revoking/);
  });

  test('FAILS when the app role can read auth.users directly', async () => {
    const { query } = await fresh(`
      create schema auth;
      create table auth.users (id uuid primary key, email text);
      grant usage on schema auth to authenticated;
      grant select on auth.users to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'auth-schema');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.where, 'auth.users');
    assert.match(v.message, /every tenant's users, emails/);
    assert.match(v.fix, /profiles table with RLS/);
  });

  test('does NOT flag an auth table the role cannot read', async () => {
    const { query } = await fresh(`
      create schema auth;
      create table auth.users (id uuid primary key, email text);
      -- no grant to authenticated
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('does NOT flag a capability the role cannot execute', async () => {
    const { query } = await fresh(`
      create function dblink(text, text) returns setof record language sql as $$ select 1, 'x' $$;
      revoke execute on function dblink(text, text) from public;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('allowlist exempts a capability granted on purpose', async () => {
    const setup = `
      create function dblink(text, text) returns setof record language sql as $$ select 1, 'x' $$;
      grant execute on function dblink(text, text) to authenticated;
    `;
    assert.equal((await check({ query: (await fresh(setup)).query })).ok, false);
    const okd = await check({ query: (await fresh(setup)).query, config: { allowlist: ['public.dblink'] } });
    assert.equal(okd.ok, true, JSON.stringify(okd, null, 2));
  });

  test('clean database with none of these capabilities passes quietly', async () => {
    const { query } = await fresh(`create table t (id int);`);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.match(res.summary, /no RLS-bypassing capability/);
  });
}
