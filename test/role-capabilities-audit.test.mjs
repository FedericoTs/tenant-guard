/**
 * role-capabilities — the four things the audit caught, each pinned by the
 * measurement that caught it.
 *
 * Three were remediation that ran clean and changed nothing (the REVOKE named a
 * grantee that did not hold the privilege), one was a build failure on access the
 * database refuses. Every test below fails against the pre-fix guard: verified by
 * reverting the guard and re-running.
 *
 * The integration arms do not assert on text alone — they apply the emitted SQL
 * and then measure the privilege, because "the fix runs" and "the fix works" came
 * apart here in exactly the way that matters.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  classifyFunction,
  classifyAuthTable,
  revokeAdvice,
  DEFAULTS,
} from '../src/guards/role-capabilities.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('role-capabilities audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec('create role authenticated nologin;');
  await db.exec(setup);
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

/** The runnable statement out of a fix block: everything up to the first caveat. */
const firstStatement = (fix) => fix.split('\n')[0];

// ── the fix names the grantee that actually holds it ──────────────────

test('auth-table fix names PUBLIC when PUBLIC is where the grant lives', () => {
  const v = classifyAuthTable({ table: 'users', role: 'authenticated', grantees: ['PUBLIC'] });
  assert.match(v.fix, /REVOKE SELECT ON auth\.users FROM PUBLIC;/);
  // and it must not print the name that would have been a no-op
  assert.ok(!/FROM authenticated;/.test(v.fix), v.fix);
});

test('a privilege held through role membership is revoked at the role that holds it', () => {
  const v = classifyFunction({
    schema: 'ext', name: 'dblink', args: 'text, text', family: 'rls-bypass',
    role: 'authenticated', grantees: ['db_helpers'],
  });
  assert.match(v.fix, /REVOKE EXECUTE ON FUNCTION ext\.dblink\(text, text\) FROM db_helpers;/);
  assert.match(v.fix, /inherits it through membership in db_helpers/);
  assert.match(v.fix, /REVOKE db_helpers FROM authenticated;/);
});

test('with no ACL read, the advice still warns about BOTH ways a REVOKE misses', () => {
  const out = revokeAdvice({ verb: 'EXECUTE', object: 'FUNCTION public.dblink(text)', role: 'authenticated' });
  assert.match(out, /FROM authenticated, PUBLIC;/);
  assert.match(out, /lives on PUBLIC/);
  assert.match(out, /through membership in another role/); // the half that used to be missing
});

test('a grantee name out of the catalog is quoted, because a REVOKE that misnames a role fails outright', () => {
  const out = revokeAdvice({ verb: 'SELECT', object: 'auth.users', role: 'authenticated', grantees: ['Data Team'] });
  // unquoted, `Data Team` is a syntax error and `MyRole` folds to `myrole` -> 42704
  assert.match(out, /FROM "Data Team";/);
  // PUBLIC is a keyword in this position, not a role name, so it stays bare
  assert.match(
    revokeAdvice({ verb: 'SELECT', object: 'auth.users', role: 'authenticated', grantees: ['PUBLIC'] }),
    /FROM PUBLIC;/,
  );
});

test('a role that bypasses the grant system is told so, not handed a REVOKE that cannot work', () => {
  const out = revokeAdvice({ verb: 'SELECT', object: 'auth.users', role: 'authenticated', grantees: [] });
  assert.ok(!/^REVOKE/.test(out), out);
  assert.match(out, /SUPERUSER/);
});

// ── urlencode is not egress ───────────────────────────────────────────

test('urlencode is not on the egress list — it encodes a string, it does not call out', () => {
  assert.ok(!DEFAULTS.egressFunctions.includes('urlencode'));
  assert.ok(!DEFAULTS.rlsBypassFunctions.includes('urlencode'));
  // the functions that actually issue the request are still all there
  for (const f of ['http', 'http_get', 'http_post', 'http_put', 'http_delete', 'http_head']) {
    assert.ok(DEFAULTS.egressFunctions.includes(f), `${f} should still be surfaced`);
  }
});

if (PGlite) {
  test('applied literally, the auth-table fix actually closes a PUBLIC-granted auth.users', async () => {
    const { db, query } = await fresh(`
      create schema auth;
      create table auth.users (id int primary key, email text);
      insert into auth.users values (1, 'a@x'), (2, 'b@x');
      grant usage on schema auth to public;
      grant select on auth.users to public;   -- the grant is on PUBLIC, never on the role
    `);
    const before = await check({ query });
    const v = before.violations.find((x) => x.where === 'auth.users');
    assert.ok(v, JSON.stringify(before, null, 2));

    await db.exec(firstStatement(v.fix));

    const priv = (await db.query(`select has_table_privilege('authenticated','auth.users','SELECT') as p`)).rows[0];
    assert.equal(priv.p, false, 'the emitted REVOKE must actually take the privilege away');
    await db.exec('begin');
    await db.exec('set local role authenticated');
    await assert.rejects(db.query('select count(*) from auth.users'));
    await db.exec('rollback');
    assert.equal((await check({ query })).ok, true, 'and the guard must go green after its own advice');
  });

  test('applied literally, the function fix clears a privilege inherited through a group role', async () => {
    const { db, query } = await fresh(`
      create role db_helpers nologin;
      create schema ext;
      grant usage on schema ext to authenticated;
      create function ext.dblink(a text, b text) returns text language sql as $$ select 'x' $$;
      revoke execute on function ext.dblink(text, text) from public;
      grant execute on function ext.dblink(text, text) to db_helpers;
      grant db_helpers to authenticated;      -- held only through membership
    `);
    const before = await check({ query });
    const v = before.violations.find((x) => x.kind === 'rls-bypass');
    assert.ok(v, JSON.stringify(before, null, 2));
    assert.match(v.fix, /FROM db_helpers;/);

    await db.exec(firstStatement(v.fix));
    const priv = (await db.query(`select has_function_privilege('authenticated','ext.dblink(text,text)','EXECUTE') as p`)).rows[0];
    assert.equal(priv.p, false, 'revoking from authenticated alone was measured as a no-op — the fix must name db_helpers');
    assert.equal((await check({ query })).ok, true);
  });

  test('a grant with no USAGE on the schema is a NOTE — the read the guard claimed is refused', async () => {
    const { db, query } = await fresh(`
      create schema auth;
      create table auth.users (id int primary key, email text);
      grant select on auth.users to authenticated;   -- no grant usage on schema auth
    `);
    // what the database actually does, before asking the guard
    await db.exec('begin');
    await db.exec('set local role authenticated');
    await assert.rejects(db.query('select count(*) from auth.users'), /permission denied for schema auth/);
    await db.exec('rollback');

    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2)); // never a build failure over access that does not exist
    assert.equal(res.violations.length, 0);
    const n = res.notes.find((x) => x.where === 'auth.users');
    assert.ok(n, JSON.stringify(res.notes, null, 2)); // and never silent either — the grant is one GRANT USAGE from real
    assert.match(n.message, /no USAGE on schema auth/);
    assert.match(n.message, /GRANT USAGE ON SCHEMA auth/);
  });

  test('the same gate on functions: EXECUTE without schema USAGE does not fail the build', async () => {
    const { query } = await fresh(`
      create schema ext;
      create function ext.pg_read_file(t text) returns text language sql as $$ select 'x' $$;
      -- PUBLIC keeps the default EXECUTE, but nobody has USAGE on ext
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.ok(res.notes.some((n) => /pg_read_file/.test(n.where) && /no USAGE on schema ext/.test(n.message)));
  });

  test('schema USAGE held via PUBLIC or via a group still reads as a leak — the gate costs no true positive', async () => {
    const viaPublic = await fresh(`
      create schema auth;
      create table auth.users (id int primary key);
      insert into auth.users values (1);
      grant usage on schema auth to public;
      grant select on auth.users to authenticated;
    `);
    // measured, not assumed: the role really can read it
    await viaPublic.db.exec('begin');
    await viaPublic.db.exec('set local role authenticated');
    assert.equal((await viaPublic.db.query('select count(*) from auth.users')).rows[0].count, 1);
    await viaPublic.db.exec('rollback');
    assert.equal((await check({ query: viaPublic.query })).ok, false);

    const viaGroup = await fresh(`
      create role grp nologin;
      grant grp to authenticated;
      create schema auth;
      create table auth.users (id int primary key);
      insert into auth.users values (1);
      grant usage on schema auth to grp;
      grant select on auth.users to grp;
    `);
    await viaGroup.db.exec('begin');
    await viaGroup.db.exec('set local role authenticated');
    assert.equal((await viaGroup.db.query('select count(*) from auth.users')).rows[0].count, 1);
    await viaGroup.db.exec('rollback');
    const res = await check({ query: viaGroup.query });
    assert.equal(res.ok, false);
    assert.match(res.violations[0].fix, /FROM grp;/);
  });

  test('a reachable urlencode says nothing at all — no violation, no SSRF note', async () => {
    const { query } = await fresh(`
      create schema ext;
      grant usage on schema ext to authenticated;
      create function ext.urlencode(t text) returns text language sql immutable as $$ select t $$;
      create function ext.http_get(t text) returns int language sql as $$ select 200 $$;
      revoke execute on function ext.http_get(text) from public;   -- outbound HTTP is locked down
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.deepEqual(res.notes, [], 'a hardened database must not be told it has SSRF exposure');
    assert.equal(res.scanned, 0);
  });

  test('a non-Supabase database stays quiet — the auth query returns no rows, it does not error', async () => {
    const { query } = await fresh('create table t (id int);');
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.deepEqual(res.notes, []); // no auth schema is not a failed check, so no "did not run" note
  });

  test('an auth-schema check that could not run says so instead of reporting clear', async () => {
    // the only way to see a failed check is to fail the query; the guard used to
    // swallow this and return ok:true with nothing said
    const query = async (text) => {
      if (/nspname = 'auth'/.test(text)) throw new Error('boom');
      return { rows: [] };
    };
    const res = await check({ query });
    assert.equal(res.ok, true); // still not a build failure — it is not a finding
    const n = res.notes.find((x) => x.where === 'auth.*');
    assert.ok(n, JSON.stringify(res.notes, null, 2));
    assert.match(n.message, /did not run: boom/);
    assert.match(n.message, /not clear of it/);
  });

  test('real outbound HTTP is still surfaced, and its REVOKE names the grantee that has it', async () => {
    const { db, query } = await fresh(`
      create function http_post(a text, b text) returns int language sql as $$ select 200 $$;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true);
    const n = res.notes.find((x) => /http_post/.test(x.where));
    assert.ok(n, JSON.stringify(res.notes, null, 2));
    assert.match(n.message, /outbound HTTP/);
    // proacl is null here, so the default PUBLIC EXECUTE is what confers it
    assert.match(n.message, /FROM PUBLIC;/);
    await db.exec(n.message.slice(n.message.lastIndexOf('REVOKE')));
    const priv = (await db.query(`select has_function_privilege('authenticated','public.http_post(text,text)','EXECUTE') as p`)).rows[0];
    assert.equal(priv.p, false);
  });
}
