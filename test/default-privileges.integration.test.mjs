/**
 * default-privileges against a real database.
 *
 * The first test is the one that matters: it shows the *time bomb* going off.
 * Every guard passes against the database as it stands, then one `create table`
 * — the ordinary thing a developer does next week — leaves an unprotected table
 * readable by `anon`, with no migration diff showing a security change.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check, probeCreateSql } from '../src/guards/default-privileges.mjs';
import { check as checkAnonReads } from '../src/guards/anon-reads.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('default-privileges integration (pglite not installed — skipped)', { skip: true }, () => {});
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

if (PGlite) {
  // ── the time bomb ──────────────────────────────────────────────────
  test('DEMONSTRATES the time bomb: today green, one create table later exposed', async () => {
    const { db, query } = await freshDb(`
      alter default privileges in schema public grant select on tables to anon;
      create table invoices (id int, organization_id text);
      alter table invoices enable row level security;
      create policy p on invoices using (organization_id = current_setting('app.tenant', true));
      grant select on invoices to anon;
    `);

    // Today: the existing table is properly protected, and anon-reads agrees.
    const before = await checkAnonReads({ query, config: { role: 'anon' } });
    assert.equal(before.ok, true, JSON.stringify(before, null, 2));

    // Next week, somebody adds a table. Nothing else about the migration is
    // unusual — no GRANT, no security statement of any kind.
    await db.exec('create table notes (id int, organization_id text, body text)');
    await db.exec(`insert into notes values (1, 'org_A', 'SECRET')`);

    // It arrived granted to anon and with RLS off.
    const after = await checkAnonReads({ query, config: { role: 'anon' } });
    assert.equal(after.ok, false, 'the new table should now be anon-readable');
    assert.ok(after.violations.some((v) => v.where.includes('notes')));
  });

  test('CATCHES it before the table exists: PUBLIC in the default privileges fails the build', async () => {
    const { query } = await freshDb('alter default privileges in schema public grant select on tables to public;');
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1);
    assert.equal(res.violations[0].where, 'public');
    assert.match(res.violations[0].message, /PUBLIC is every role/);
    assert.match(res.violations[0].message, /rolled-back transaction/);
  });

  test('the probe leaves NOTHING behind — the table is rolled back', async () => {
    const { db, query } = await freshDb('alter default privileges in schema public grant select on tables to public;');
    await check({ query });
    const left = await db.query(`select count(*)::int as n from pg_class where relname = 'tg_default_privileges_probe'`);
    assert.equal(left.rows[0].n, 0);
  });

  test('NOTE not failure for the stock shape: anon/authenticated named explicitly', async () => {
    const { query } = await freshDb(`
      alter default privileges in schema public grant select on tables to anon;
      alter default privileges in schema public grant all on tables to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, 'must not fail every Supabase project');
    const note = res.notes.find((n) => n.where === 'public');
    assert.ok(note);
    assert.match(note.message, /anon/);
    assert.match(note.message, /next week/);
  });

  test('failRoles escalates that same database to a build failure', async () => {
    const { query } = await freshDb('alter default privileges in schema public grant select on tables to anon;');
    const res = await check({ query, config: { failRoles: ['PUBLIC', 'anon'] } });
    assert.equal(res.ok, false);
    assert.match(res.violations[0].message, /anon/);
  });

  test('PASSES when a new table inherits nothing beyond its owner', async () => {
    const { query } = await freshDb('create table invoices (id int);');
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.notes.filter((n) => n.where === 'public').length, 0);
    assert.equal(res.scanned, 1);
  });

  test('an event trigger that forces RLS downgrades the finding', async () => {
    const { query } = await freshDb(`
      alter default privileges in schema public grant select on tables to public;
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
    assert.equal(res.ok, true, 'a database that already forces RLS must not be nagged');
    assert.match(res.notes.find((n) => n.where === 'public').message, /event trigger/);
  });

  test('an allowlisted schema is skipped entirely', async () => {
    const { query } = await freshDb('alter default privileges in schema public grant select on tables to public;');
    const res = await check({ query, config: { allowlist: ['public'] } });
    assert.equal(res.skipped, true); // nothing left to probe
  });

  test('a schema it cannot create in is reported as unproven, never as a pass', async () => {
    const { query } = await freshDb('create schema locked;');
    const res = await check({ query, config: { schemas: ['nonexistent_schema'] } });
    assert.equal(res.skipped, true);
    assert.match(res.reason, /could not create a probe table/);
    assert.match(res.notes[0].message, /unproven/);
  });

  test('probeCreateSql refuses an unsafe identifier rather than interpolating it', () => {
    assert.throws(() => probeCreateSql('public', 'x"; drop table invoices; --'));
  });
}
