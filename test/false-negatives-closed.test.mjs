/**
 * Seven ways a guard reported clean on something it should have caught.
 *
 * All seven were reproduced against a real database before the fix, and each
 * test below fails without it. They share a theme worth naming: every one is a
 * place where the guard stopped looking early — at pg_catalog, at a declared
 * volatility, at a read probe, at the first error, at a bare object name.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { shadowableSchemas } from '../src/guards/definer-rpc.mjs';
import { extractFunctionDefs, bodyCallsUserFunction } from '../src/guards/definer-grants.mjs';
import { prove } from '../src/guards/rls-proof.mjs';
import { check as anonReads } from '../src/guards/anon-reads.mjs';
import { check as anonWrites, impliesWritePermitted } from '../src/guards/anon-writes.mjs';
import { run as uvwRun, extractViews, qualifiedName } from '../src/guards/updatable-view-writethrough.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('false-negatives-closed (pglite not installed — skipped)', { skip: true }, () => {});
}

const q = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

// ── 1. shadowableSchemas walked past pg_catalog ──────────────────────

test('1. a writable schema AFTER pg_catalog and before the home schema is reported', () => {
  assert.deepEqual(shadowableSchemas(['search_path=pg_catalog, public, app'], ['public'], 'app'), ['public']);
});

test('1. …but public on `pg_catalog, public` for a function IN public is not', () => {
  // Reporting it would fire on essentially every Supabase project: nothing
  // precedes the real object, and a CREATE in the same schema collides.
  assert.deepEqual(shadowableSchemas(['search_path=pg_catalog, public'], ['public'], 'public'), []);
});

// ── 2. STABLE is not proof a function cannot write ───────────────────

test('2. a non-volatile definer function that calls out is flagged as unknown, not clean', () => {
  const [fn] = extractFunctionDefs(
    `create function f() returns void language plpgsql stable security definer as $s$ begin perform helper(); end; $s$;`);
  assert.equal(fn.mutationUnknown, true);
  assert.equal(fn.mutates, false, 'still not a violation on its own — that drove the 0.26.0 REVOKE advice');
});

test('2. …and a pure STABLE predicate is left alone', () => {
  const [fn] = extractFunctionDefs(
    `create function g() returns bool language sql stable security definer as $s$ select true $s$;`);
  assert.equal(fn.mutationUnknown, false);
});

test('2. bodyCallsUserFunction ignores built-ins', () => {
  assert.equal(bodyCallsUserFunction(`begin return coalesce(current_setting('x', true), 'y'); end;`), false);
  assert.equal(bodyCallsUserFunction(`begin perform my_helper(); end;`), true);
});

if (PGlite) {
  test('2. DEMONSTRATES it: a STABLE function writes through a VOLATILE callee', async () => {
    const db = new PGlite();
    await db.exec(`
      create table audit (v text);
      create function helper() returns void language plpgsql volatile as $h$ begin insert into audit values ('x'); end; $h$;
      create function f_stable() returns void language plpgsql stable security definer as $s$ begin perform helper(); end; $s$;`);
    await db.query('select f_stable()');
    assert.equal((await db.query('select count(*)::int n from audit')).rows[0].n, 1);
  });

  // ── 3. the single-tenant branch never probed writes ────────────────

  async function twoTables(invoicePolicies) {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table members (id serial primary key, organization_id text);
      insert into members (organization_id) values ('org_A'),('org_B');
      alter table members enable row level security;
      create policy m on members for all to authenticated
        using (organization_id = current_setting('app.current_tenant', true))
        with check (organization_id = current_setting('app.current_tenant', true));
      grant select, insert, update, delete on members to authenticated;
      create table invoices (id serial primary key, organization_id text);
      insert into invoices (organization_id) values ('org_A');   -- ONE tenant
      alter table invoices enable row level security;
      ${invoicePolicies}
      grant select, insert, update, delete on invoices to authenticated;`);
    return prove({
      query: q(db),
      config: {
        role: 'authenticated',
        becomeTenant: ["select set_config('app.current_tenant', $1, true)"],
        tenantColumns: ['organization_id'],
      },
    });
  }

  test('3. a single-tenant table with a wide-open UPDATE is caught', async () => {
    const res = await twoTables(`
      create policy i_sel on invoices for select to authenticated
        using (organization_id = current_setting('app.current_tenant', true));
      create policy i_upd on invoices for update to authenticated using (true) with check (true);
      create policy i_del on invoices for delete to authenticated using (true);`);
    assert.equal(res.ok, false, JSON.stringify(res.summary));
    assert.ok(res.violations.some((v) => /invoices/.test(v.where) && v.kind === 'write'));
  });

  test('3. …and a correctly-scoped one still passes', async () => {
    const res = await twoTables(`
      create policy i_all on invoices for all to authenticated
        using (organization_id = current_setting('app.current_tenant', true))
        with check (organization_id = current_setting('app.current_tenant', true));`);
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  // ── 4. one unreadable relation lost the whole anon-reads scan ──────

  test('4. an unpopulated matview no longer aborts the scan', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin; grant usage on schema public to anon;
      create table orders (id int, organization_id text);
      insert into orders values (1,'org_A'),(2,'org_B');
      grant select on orders to anon;                       -- a real leak: RLS off
      create materialized view order_rollup as select organization_id, count(*) n from orders group by 1 with no data;
      grant select on order_rollup to anon;`);
    const res = await anonReads({ query: q(db), config: { role: 'anon' } }); // used to throw 55000
    assert.equal(res.ok, false, 'the real leak must still be reported');
    assert.ok(res.violations.some((v) => /orders/.test(v.where)));
  });

  // ── 5. the DELETE probe was defeated by a foreign key ──────────────

  test('5. impliesWritePermitted reads a constraint violation as "rows got through"', () => {
    assert.equal(impliesWritePermitted({ code: '23503' }), true);
    assert.equal(impliesWritePermitted({ code: '42501' }), false);
    assert.equal(impliesWritePermitted({ code: '25P02' }), false);
  });

  async function fkTable(policy) {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin; grant usage on schema public to anon;
      create table users (id int primary key); insert into users values (1);
      alter table users enable row level security;
      ${policy}
      grant select, insert, update, delete on users to anon;
      create table orders (id int, user_id int references users(id));
      insert into orders values (1,1);`);
    return anonWrites({ query: q(db), config: { role: 'anon' } });
  }

  test('5. DELETE is reported on an FK-referenced table anon can really delete from', async () => {
    const res = await fkTable(`create policy p on users for all to anon using (true) with check (true);`);
    const v = res.violations.find((x) => /users/.test(x.where));
    assert.ok(v, JSON.stringify(res, null, 2));
    assert.match(v.message, /DELETE/);
  });

  test('5. …and a table the policy denies is still silent', async () => {
    const res = await fkTable(`create policy p on users for all to anon using (false);`);
    assert.equal(res.violations.some((x) => /users/.test(x.where)), false, JSON.stringify(res, null, 2));
  });
}

// ── 6. DROP VIEW + CREATE VIEW resets the ACL ────────────────────────

function withMigrations(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-fn-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const REVOKED = `
  alter default privileges in schema public grant select, insert, update, delete on tables to anon, authenticated;
  create view public_profiles as select id, display_name from profiles;
  revoke insert, update, delete on public_profiles from anon, authenticated;`;

test('6. a REVOKE before a DROP VIEW does not protect the recreated view', () => {
  withMigrations({
    '001.sql': REVOKED,
    '010.sql': 'drop view public_profiles;\ncreate view public_profiles as select id, display_name, bio from profiles;',
  }, (dir) => {
    assert.equal(uvwRun({ dir }).ok, false, 'the recreated view gets fresh default privileges');
  });
});

test('6. …and re-revoking after the recreate clears it again', () => {
  withMigrations({
    '001.sql': REVOKED,
    '010.sql': 'drop view public_profiles;\ncreate view public_profiles as select id from profiles;\n'
             + 'revoke insert, update, delete on public_profiles from anon, authenticated;',
  }, (dir) => {
    assert.equal(uvwRun({ dir }).ok, true);
  });
});

// ── 7. two same-named views in different schemas collapsed ───────────

test('7. qualifiedName defaults an unqualified name to public', () => {
  assert.equal(qualifiedName('profiles'), 'public.profiles');
  assert.equal(qualifiedName('reporting.profiles'), 'reporting.profiles');
  assert.equal(qualifiedName('"Reporting"."Profiles"'), 'reporting.profiles');
});

test('7. two same-named views in different schemas stay distinct', () => {
  // Keyed by bare name, the reporting view overwrote the real one and the
  // write-through went unreported.
  const views = extractViews(
    'create view public.profiles as select id, email from users;'
    + ' create view reporting.profiles as select count(*) n from users;');
  assert.deepEqual(views.map((v) => v.qualified), ['public.profiles', 'reporting.profiles']);
  assert.equal(new Set(views.map((v) => v.qualified)).size, 2);
});
