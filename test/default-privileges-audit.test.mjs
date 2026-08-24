/**
 * default-privileges — audit regressions.
 *
 * One finding, two halves, both reproduced against pglite before anything was
 * changed:
 *
 *   1. `check()` only ever created its probe table as the *connecting* role, so
 *      `ALTER DEFAULT PRIVILEGES FOR ROLE <migrator> ... GRANT SELECT ON TABLES
 *      TO PUBLIC` — the one shape this guard is configured to fail on — came
 *      back `{ ok: true, violations: 0, notes: [] }`. Measured on the same
 *      database: `set local role migrator; create table public.customers (...)`
 *      arrived `{=r/migrator,anon=arwd/migrator,...}` with `relrowsecurity =
 *      false`, and `set local role anon; select secret from customers` returned
 *      the row. Green build, armed leak. CI connecting as one role while
 *      migrations run as another is the ordinary deployment, and it is exactly
 *      the case where the CI role *can* CREATE — so the guard did not even fall
 *      back to its "could not create a probe table" skip note. It asserted a
 *      pass.
 *
 *   2. The emitted remediation was a no-op. `ALTER DEFAULT PRIVILEGES IN SCHEMA
 *      public REVOKE ALL ON TABLES FROM PUBLIC` run as the admin left
 *      `pg_default_acl` byte-identical (`creator=migrator, defaclacl={=r/migrator}`)
 *      and the next table `migrator` created was still PUBLIC-readable. Without
 *      `FOR ROLE` the statement edits the executing role's own defaults. It
 *      succeeds, and it changes nothing.
 *
 * The calibration half matters as much: probing more roles must not turn the
 * stock Supabase shape (anon/authenticated, never PUBLIC) into a build failure,
 * and a role the guard cannot become must produce a note that says so — never a
 * violation inferred from a catalog row it could not verify.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check, classifyInherited, quoteGrantee } from '../src/guards/default-privileges.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('default-privileges audit (pglite not installed — skipped)', { skip: true }, () => {});
}

async function freshDb(setup) {
  const db = new PGlite();
  await db.exec(`
    create role anon nologin;
    create role authenticated nologin;
    grant usage on schema public to anon, authenticated;
  `);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

/** Every line of a `fix` that is actually a SQL statement, in order. */
const statementsIn = (fix) =>
  fix
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.endsWith(';'));

// ── the false negative ───────────────────────────────────────────────

if (PGlite) {
  test('FOR ROLE <other>: a PUBLIC grant on another role\'s defaults fails the build', async () => {
    const { query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on tables to public;
    `);
    const res = await check({ query });
    // Before the fix this was ok:true, violations:[], notes:[] — a fully green
    // run on a database where migrator's next `create table` is world-readable.
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1);
    assert.equal(res.violations[0].kind, 'inherited-grant');
    assert.match(res.violations[0].where, /migrator/);
  });

  test('the leak it now reports is real: migrator\'s next table is readable by anon', async () => {
    // The guard's claim, checked independently. This is the fact the green run
    // was hiding, not a restatement of the guard's own output.
    const { db, query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public
        grant select, insert, update, delete on tables to anon;
      alter default privileges for role migrator in schema public grant select on tables to public;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false);

    await db.exec(`begin; set local role migrator; create table public.customers (id int, secret text);`);
    await db.exec(`insert into public.customers values (1, 'top secret');`);
    await db.exec(`set local role anon;`);
    const seen = await db.query('select secret from public.customers');
    await db.exec('rollback');
    assert.deepEqual(seen.rows, [{ secret: 'top secret' }], 'anon reads a table it never was granted directly');
  });

  test('every verdict names the role it answers for — a probe speaks for one role only', async () => {
    const { query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on tables to public;
    `);
    const res = await check({ query });
    assert.match(res.violations[0].message, /by migrator/);
    // and the summary says whose defaults were actually exercised
    assert.match(res.summary, /probe\(s\)/);
  });

  // ── the advice ─────────────────────────────────────────────────────

  test('the emitted fix runs verbatim and actually closes the finding', async () => {
    const { db, query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on tables to public;
      create table public.legacy (i int);
    `);
    const before = await check({ query });
    const fix = before.violations[0].fix;
    assert.match(fix, /FOR ROLE "migrator"/, 'without FOR ROLE the statement edits the executor\'s own defaults');

    for (const stmt of statementsIn(fix)) {
      await db.exec(stmt); // throws if the advice is not runnable SQL
    }

    const after = await check({ query });
    assert.equal(after.ok, true, JSON.stringify(after, null, 2));
    assert.equal(after.notes.length, 0);
  });

  test('the OLD advice is a no-op — which is why FOR ROLE is in the emitted line', async () => {
    // Pinning the measurement, so nobody "simplifies" FOR ROLE back out.
    const { db, query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on tables to public;
    `);
    await db.exec('alter default privileges in schema public revoke all on tables from public;');
    const res = await check({ query });
    assert.equal(res.ok, false, 'the un-parameterised REVOKE succeeded and changed nothing');
  });

  // ── calibration: it must not fire on correct code ───────────────────

  test('a separate migration role with the STOCK Supabase shape is a note, not a failure', async () => {
    const { query } = await freshDb(`
      create role supabase_admin superuser;
      alter default privileges for role supabase_admin in schema public grant select on tables to anon;
      alter default privileges for role supabase_admin in schema public grant all on tables to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, 'must not fail every Supabase project just because the creator differs');
    const note = res.notes.find((n) => n.where.includes('supabase_admin'));
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /by supabase_admin/);
    assert.match(note.message, /UNAUTHENTICATED role \(anon\)/);
  });

  test('a database with no default privileges at all stays completely silent', async () => {
    const { query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      create table invoices (id int);
    `);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.deepEqual(res.notes, [], 'extra roles existing is not a finding');
    assert.equal(res.scanned, 1, 'no FOR ROLE entries means nothing extra to probe');
  });

  test('a creator with SEQUENCE-only defaults is not probed as if it were tables', async () => {
    const { query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on sequences to public;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.equal(res.scanned, 1);
  });

  test('an event trigger that forces RLS downgrades the other role\'s finding too', async () => {
    const { query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on tables to public;
      create function force_rls() returns event_trigger language plpgsql as $$
      declare r record;
      begin
        for r in select * from pg_event_trigger_ddl_commands() where command_tag = 'CREATE TABLE' loop
          execute format('alter table %s enable row level security', r.object_identity);
        end loop;
      end $$;
      create event trigger force_rls_trg on ddl_command_end execute function force_rls();
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, 'a database that already forces RLS must not be nagged for any creator');
    assert.match(res.notes.find((n) => n.where.includes('migrator')).message, /already ENABLED/);
  });

  test('the extra probes leave NOTHING behind either', async () => {
    const { db, query } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on tables to public;
    `);
    await check({ query });
    const left = await db.query(
      `select count(*)::int as n from pg_class where relname = 'tg_default_privileges_probe'`,
    );
    assert.equal(left.rows[0].n, 0);
    // and the connection is not left wearing the borrowed role
    const who = await db.query('select current_user as role');
    assert.notEqual(who.rows[0].role, 'migrator');
  });

  // ── a skip is never a pass ──────────────────────────────────────────

  test('a creator the guard cannot become is a NOTE naming it, never a violation', async () => {
    // Simulated by refusing the SET ROLE, because pglite connects as a
    // superuser and a superuser can become anyone. The refusal message is the
    // one Postgres gives a non-member.
    const { query: raw } = await freshDb(`
      create role migrator;
      grant create, usage on schema public to migrator;
      alter default privileges for role migrator in schema public grant select on tables to public;
    `);
    const query = async (text, values) => {
      if (/^set local role/i.test(text.trim())) {
        throw new Error('permission denied to set role "migrator"');
      }
      return raw(text, values);
    };
    const res = await check({ query });
    assert.equal(res.ok, true, 'an unverified catalog row must not fail the build');
    assert.equal(res.violations.length, 0);
    const note = res.notes.find((n) => n.where.includes('migrator'));
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /unproven/);
    assert.match(note.message, /GRANT migrator TO/); // and how to make it provable
  });

  test('an unreadable pg_default_acl says the run only answers for one role', async () => {
    const { query: raw } = await freshDb('create table invoices (id int);');
    const query = async (text, values) => {
      if (/pg_default_acl/.test(text)) throw new Error('permission denied for table pg_default_acl');
      return raw(text, values);
    };
    const res = await check({ query });
    const note = res.notes.find((n) => n.where === '(pg_default_acl)');
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /only answers/);
    assert.match(note.message, /FOR ROLE/);
  });
}

// ── pure logic ───────────────────────────────────────────────────────

test('quoteGrantee: PUBLIC is a keyword, everything else is a quoted identifier', () => {
  assert.equal(quoteGrantee('PUBLIC'), 'PUBLIC'); // "PUBLIC" would mean a role of that name
  assert.equal(quoteGrantee('anon'), '"anon"');
  assert.equal(quoteGrantee('weird"role'), '"weird""role"');
});

test('the REVOKE names the roles that actually failed, not PUBLIC by assumption', () => {
  // With failRoles: ['anon'] the old text said "REVOKE ... FROM PUBLIC", which
  // runs clean and leaves anon's grant exactly where it was.
  const v = classifyInherited({
    schema: 'public',
    creator: 'migrator',
    grants: [{ grantee: 'anon', privileges: ['SELECT'], writes: false }],
    config: { failRoles: ['anon'] },
  });
  assert.equal(v.status, 'leak');
  assert.match(v.fix, /REVOKE ALL ON TABLES FROM "anon";/);
  assert.doesNotMatch(v.fix, /FROM PUBLIC/);
  assert.doesNotMatch(v.message, /every role that exists or ever will/); // that is only true of PUBLIC
});

test('the FOR ROLE clause is present whenever the probing role is known', () => {
  const v = classifyInherited({
    schema: 'public',
    creator: 'migrator',
    grants: [{ grantee: 'PUBLIC', privileges: ['SELECT'], writes: false }],
  });
  assert.match(v.fix, /ALTER DEFAULT PRIVILEGES FOR ROLE "migrator" IN SCHEMA public/);
  assert.match(v.fix, /FOR ROLE is not optional/);
});

test('the existing-tables REVOKE is a complete statement, not an ellipsis', () => {
  const v = classifyInherited({
    schema: 'public',
    grants: [{ grantee: 'PUBLIC', privileges: ['SELECT'], writes: false }],
  });
  // It used to read "run REVOKE ... ON ALL TABLES IN SCHEMA public FROM PUBLIC",
  // which is not SQL. Every line ending in ';' has to be runnable.
  for (const stmt of statementsIn(v.fix)) assert.doesNotMatch(stmt, /\.\.\./);
  assert.match(v.fix, /REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;/);
});

test('every verdict names the creating role when it is known', () => {
  const grants = [{ grantee: 'reporting', privileges: ['SELECT'], writes: false }];
  assert.match(classifyInherited({ schema: 'public', creator: 'migrator', grants }).message, /by migrator/);
  assert.match(classifyInherited({ schema: 'public', creator: 'migrator', grants: [] }).message, /by migrator/);
  assert.match(
    classifyInherited({ schema: 'public', creator: 'migrator', grants, rlsEnabled: true }).message,
    /by migrator/,
  );
});
