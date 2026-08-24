/**
 * Audit follow-ups for trigger-visibility.
 *
 * Three defects, all reproduced against a real database before being changed:
 *
 *  1. An append-only audit trigger (AFTER INSERT, writes a row, RETURN NULL)
 *     failed the build. `enforcesSomething` counted RETURN NULL without knowing
 *     the trigger was AFTER — where the return value is discarded — and
 *     `tablesRead` counted the INSERT *target* as a read. Measured: the guard
 *     said `audit_orders … enforces a rule by reading public.audit_log (0 of 1
 *     rows visible)` about a function that reads nothing and cancels nothing.
 *
 *  2. The remediation emitted `ALTER FUNCTION <table_schema>.<function>()`
 *     because the query never selected the function's own namespace. With the
 *     function in `private`, that statement errors — and when a same-named
 *     function exists in `public`, it SUCCEEDS against the wrong function,
 *     leaving the finding open and gratuitously promoting a bystander to
 *     SECURITY DEFINER.
 *
 *  3. `tablesRead` matched the bare table name anywhere in `prosrc`, so
 *     `raise exception 'audit_log is append-only'` — a body containing no query
 *     at all — was reported as "enforcing a rule by reading public.audit_log
 *     (0 of 4 rows visible)". Changing only the message text silenced it.
 *
 * The catch cases are repeated here as the floor: narrowing the read detector is
 * how a cry-wolf fix turns into a missed finding.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  cancelsRowOnNull,
  enforcesSomething,
  splitBody,
  tablesRead,
  classifyTrigger,
} from '../src/guards/trigger-visibility.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('trigger-visibility audit (pglite not installed — skipped)', { skip: true }, () => {});
}

const q = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

// ── pure ─────────────────────────────────────────────────────────────

test('RETURN NULL only enforces where the return value is honoured', () => {
  // tgtype values read straight out of pg_trigger in pglite.
  assert.equal(cancelsRowOnNull(7), true, 'BEFORE … FOR EACH ROW');
  assert.equal(cancelsRowOnNull(69), true, 'INSTEAD OF … FOR EACH ROW (views)');
  assert.equal(cancelsRowOnNull(5), false, 'AFTER … FOR EACH ROW — return value discarded');
  assert.equal(cancelsRowOnNull(4), false, 'AFTER … FOR EACH STATEMENT');
  assert.equal(cancelsRowOnNull(6), false, 'BEFORE … FOR EACH STATEMENT');
  // Unknown tgtype must not silently drop a finding.
  assert.equal(cancelsRowOnNull(undefined), true);
  assert.equal(cancelsRowOnNull(null), true);

  const audit = `begin insert into audit_log (t) values ('x'); return null; end;`;
  assert.equal(enforcesSomething(audit, 5), false, 'AFTER row trigger cancels nothing');
  assert.equal(enforcesSomething(audit, 7), true, 'the same body BEFORE really does cancel');
  // RAISE aborts the statement wherever it fires, so it is unconditional.
  assert.equal(enforcesSomething(`begin raise exception 'no'; end;`, 5), true);
});

test('tablesRead reads code, not prose', () => {
  const rls = ['public.audit_log', 'public.profiles'];
  // The three shapes that used to fire on a body containing no query.
  assert.deepEqual(tablesRead(`begin raise exception 'audit_log is append-only'; end`, rls), []);
  assert.deepEqual(tablesRead(`begin raise exception 'cannot delete from audit_log'; end`, rls), []);
  assert.deepEqual(tablesRead(`begin -- guards audit_log\n return new; end`, rls), []);
  assert.deepEqual(tablesRead(`begin /* audit_log stays append-only */ return new; end`, rls), []);
  // A write target is not a read: a VALUES insert consults no existing row.
  assert.deepEqual(tablesRead(`begin insert into audit_log (t) values ('x'); return null; end`, rls), []);
  // The SOURCE of an INSERT … SELECT is still a read; the target still is not.
  assert.deepEqual(
    tablesRead(`begin insert into audit_log (t) select id from profiles; return new; end`, rls),
    ['public.profiles'],
  );
  // And a read of the write target elsewhere in the body counts as a read.
  assert.deepEqual(
    tablesRead(`begin insert into audit_log (t) values ('x'); perform 1 from audit_log; end`, rls),
    ['public.audit_log'],
  );
});

test('tablesRead still catches every real read shape', () => {
  const rls = ['public.profiles'];
  const yes = [
    `if exists (select 1 from profiles where username = new.username) then raise exception 'x'; end if;`,
    `select count(*) into n from public.profiles;`,
    `select 1 from "profiles" p join other o on o.id = p.id;`,
    `perform 1 from profiles where id = new.id;`,
    `for r in select id from profiles loop end loop;`,
    `update profiles set seen = true where id = new.id;`,
    `update only profiles set seen = true;`,
    `delete from profiles where id = new.id;`,
    `merge into profiles p using src s on s.id = p.id;`,
    `delete from other o using profiles p where p.id = o.pid;`,
    // dynamic SQL: the literal is the statement, so a read inside it is a read
    `execute 'select 1 from profiles where id = $1' using new.id;`,
    `execute 'select 1 from ' || quote_ident('profiles') || ' where id=1';`,
  ];
  for (const body of yes) {
    assert.deepEqual(tablesRead(body, rls), ['public.profiles'], body);
  }
  // Word boundaries still hold, and a literal that is not executed still does not count.
  assert.deepEqual(tablesRead(`select 1 from profiles_archive`, rls), []);
  assert.deepEqual(tablesRead(`raise notice 'select 1 from profiles';`, rls), []);
});

test('splitBody keeps quoting and comments from desynchronising each other', () => {
  // `--` inside a message literal used to eat the closing quote when comments
  // were stripped in a separate pass, which corrupted everything after it.
  const { code } = splitBody(`begin raise exception 'a--b'; select 1 from profiles; end`);
  assert.match(code, /from profiles/);
  assert.doesNotMatch(code, /a--b/);
  // A dollar-quoted literal is text, not code.
  const d = splitBody(`begin execute $q$select 1 from profiles$q$; end`);
  assert.deepEqual(d.dynamic, ['select 1 from profiles']);
  assert.doesNotMatch(d.code, /select 1/);
  // `$1` is a placeholder, not a dollar-quote opener.
  assert.match(splitBody(`execute f($1) ; select 1 from profiles;`).code, /from profiles/);
});

test('the remediation targets the FUNCTION schema, not the table schema', () => {
  const v = classifyTrigger({
    trigger: {
      schema: 'public', table: 'profiles', trigger: 't', function: 'check_username',
      function_schema: 'private',
    },
    hidden: [{ table: 'public.profiles', visible: 0, total: 1 }],
    role: 'authenticated',
  });
  assert.match(v.fix, /ALTER FUNCTION private\.check_username\(\) SECURITY DEFINER;/);
  assert.doesNotMatch(v.fix, /ALTER FUNCTION public\.check_username\(\)/);
  // The body resolves unqualified names in the table schema and may call helpers
  // unqualified in its own; pg_temp must stay last.
  assert.match(v.fix, /SET search_path = pg_catalog, public, private, pg_temp;/);
  assert.match(v.message, /"private\.check_username"/);

  // A hand-built trigger object without the new field must not render `undefined.f()`.
  const legacy = classifyTrigger({
    trigger: { schema: 'public', table: 'profiles', trigger: 't', function: 'f' },
    hidden: [{ table: 'public.profiles', visible: 1, total: 9 }],
    role: 'authenticated',
  });
  assert.doesNotMatch(legacy.fix, /undefined/);
  assert.match(legacy.fix, /ALTER FUNCTION public\.f\(\)/);
  assert.match(legacy.fix, /SET search_path = pg_catalog, public, pg_temp;/);
});

// ── integration ──────────────────────────────────────────────────────

if (PGlite) {
  test('an append-only AFTER audit trigger is not a finding, and not a note either', async () => {
    // The textbook hardened audit table: RLS on, INSERT-only grant, no SELECT
    // policy and no SELECT grant. Reported before the fix as "enforces a rule by
    // reading public.audit_log (0 of 1 rows visible)" — it reads nothing, and
    // RETURN NULL from an AFTER row trigger cancels nothing.
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table orders (id serial primary key, user_id text, amount int);
      insert into orders (user_id, amount) values ('u_other', 5);
      alter table orders enable row level security;
      create policy own on orders for all to authenticated
        using (user_id = current_setting('app.uid', true))
        with check (user_id = current_setting('app.uid', true));
      grant select, insert on orders to authenticated;

      create table audit_log (id serial primary key, tbl text, note text);
      insert into audit_log (tbl, note) values ('orders', 'seed');
      alter table audit_log enable row level security;
      create policy append on audit_log for insert to authenticated with check (true);
      grant insert on audit_log to authenticated;

      create function log_order_change() returns trigger language plpgsql as $fn$
        begin
          insert into audit_log (tbl, note) values ('orders', new.id::text);
          return null;
        end;
      $fn$;
      create trigger audit_orders after insert on orders
        for each row execute function log_order_change();
    `);
    const res = await check({ query: q(db), config: { role: 'authenticated' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.equal(res.notes.length, 0, JSON.stringify(res.notes, null, 2));
  });

  test('…and RETURN NULL from an AFTER row trigger really does cancel nothing', async () => {
    // The fact the fix rests on, measured rather than assumed.
    const db = new PGlite();
    await db.exec(`
      create table t (id serial primary key, v int);
      create function f() returns trigger language plpgsql as $fn$ begin return null; end; $fn$;
      create trigger tr after insert on t for each row execute function f();
      insert into t (v) values (1);
    `);
    const n = (await db.query('select count(*)::int as n from t')).rows[0].n;
    assert.equal(n, 1, 'the "rejected" row is in the table');
  });

  test('an append-only RAISE trigger is not a finding just for naming its table', async () => {
    // Same schema twice, only the message text differs. Before the fix the first
    // failed the build and the second passed.
    const schema = (msg) => `
      create role authenticated nologin;
      create table audit_log (id serial primary key, tenant_id text, event text);
      insert into audit_log (tenant_id, event) values ('t1','a'),('t1','b'),('t2','c'),('t2','d');
      alter table audit_log enable row level security;
      create policy tenant on audit_log for all to authenticated
        using (tenant_id = current_setting('app.tenant', true));
      grant select, insert, update, delete on audit_log to authenticated;
      create function tg_append_only() returns trigger language plpgsql as $fn$
        begin raise exception '${msg}'; end; $fn$;
      create trigger audit_log_no_update before update or delete on audit_log
        for each row execute function tg_append_only();`;
    for (const msg of ['audit_log is append-only', 'this table is append-only']) {
      const db = new PGlite();
      await db.exec(schema(msg));
      const res = await check({ query: q(db), config: { role: 'authenticated' } });
      assert.equal(res.ok, true, `${msg}\n${JSON.stringify(res, null, 2)}`);
      assert.equal(res.violations.length, 0);
    }
  });

  test('an INSTEAD OF row trigger on a view still counts as enforcing', async () => {
    // The narrowing must not stop at BEFORE: an INSTEAD OF row trigger cancels
    // on NULL too (tgtype 69), and this one decides using an RLS-filtered read.
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table profiles (id serial primary key, user_id text, username text);
      insert into profiles (user_id, username) values ('u_other','taken');
      alter table profiles enable row level security;
      create policy own on profiles for all to authenticated
        using (user_id = current_setting('app.uid', true))
        with check (user_id = current_setting('app.uid', true));
      grant select, insert on profiles to authenticated;
      create view v_profiles as select * from profiles;
      grant select, insert on v_profiles to authenticated;
      create function v_ins() returns trigger language plpgsql as $fn$
        begin
          if exists (select 1 from profiles where username = new.username) then
            return null;
          end if;
          insert into profiles (user_id, username) values (new.user_id, new.username);
          return new;
        end; $fn$;
      create trigger v_profiles_ins instead of insert on v_profiles
        for each row execute function v_ins();
    `);
    const res = await check({ query: q(db), config: { role: 'authenticated' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.match(res.violations[0].where, /v_profiles_ins/);
  });

  test('the emitted ALTER runs against the right function and leaves the decoy alone', async () => {
    // Before the fix both statements ran, altered `public.check_unique_username`
    // — an unrelated function — and left the trigger's real function untouched.
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create schema private;
      create table profiles (id serial primary key, user_id text, username text);
      insert into profiles (user_id, username) values ('u_other','taken');
      alter table profiles enable row level security;
      create policy own on profiles for all to authenticated
        using (user_id = current_setting('app.uid', true))
        with check (user_id = current_setting('app.uid', true));
      grant select, insert on profiles to authenticated;
      create function private.check_unique_username() returns trigger language plpgsql as $fn$
        begin
          if exists (select 1 from profiles where username = new.username) then
            raise exception 'taken'; end if; return new; end; $fn$;
      create trigger enforce_unique_username before insert on profiles
        for each row execute function private.check_unique_username();
      -- the bystander that made the wrong advice appear to succeed
      create function public.check_unique_username() returns trigger language plpgsql as $fn$
        begin return new; end; $fn$;
    `);
    const res = await check({ query: q(db), config: { role: 'authenticated' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));

    // Advice must be safe to apply blind: run exactly what was printed.
    const alters = res.violations[0].fix
      .split('\n').map((s) => s.trim()).filter((s) => s.startsWith('ALTER FUNCTION'));
    assert.equal(alters.length, 2, alters.join('\n'));
    for (const a of alters) await db.exec(a); // must not throw

    const rows = (await db.query(`
      select n.nspname as schema, p.prosecdef, p.proconfig
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where p.proname = 'check_unique_username' order by 1`)).rows;
    const priv = rows.find((r) => r.schema === 'private');
    const pub = rows.find((r) => r.schema === 'public');
    assert.equal(priv.prosecdef, true, 'the trigger function is the one that got fixed');
    assert.ok(String(priv.proconfig).includes('pg_temp'));
    assert.equal(pub.prosecdef, false, 'the bystander must not be promoted to SECURITY DEFINER');
    assert.equal(pub.proconfig, null);
  });

  test('the original catch still fails the build (regression floor)', async () => {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table profiles (id serial primary key, user_id text, username text);
      insert into profiles (user_id, username) values ('u_other','taken');
      alter table profiles enable row level security;
      create policy own on profiles for all to authenticated
        using (user_id = current_setting('app.uid', true));
      grant select, insert on profiles to authenticated;
      create function check_username() returns trigger language plpgsql as $fn$
        begin
          if exists (select 1 from profiles where username = new.username) then
            raise exception 'username taken'; end if; return new; end; $fn$;
      create trigger t_username before insert on profiles
        for each row execute function check_username();
    `);
    const res = await check({ query: q(db), config: { role: 'authenticated' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.match(res.violations[0].message, /"public\.check_username"/);
  });
}
