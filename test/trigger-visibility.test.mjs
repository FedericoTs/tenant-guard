/**
 * Triggers that enforce a rule by reading a table RLS hides from them.
 *
 * The first integration test is the demonstration rather than an assertion about
 * the guard: a uniqueness trigger in invoker mode does not merely fail to
 * report the collision — the duplicate row is INSERTED. The identical trigger
 * marked SECURITY DEFINER raises. Hardening the table is what breaks the
 * guarantee, which makes this the purest form of the silent-failure shape.
 *
 * The calibration tests carry the weight. Every schema is full of triggers that
 * read the table they are attached to — `set_updated_at`, an audit stamp, a
 * `user_id` default — and none of them are findings. The enforcement signal
 * (RAISE, or RETURN NULL to cancel the row) is what separates a rule from a
 * record, and the visibility measurement is what makes the finding conclusive
 * rather than a guess about intent.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  enforcesSomething,
  tablesRead,
  classifyTrigger,
  check,
} from '../src/guards/trigger-visibility.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('trigger-visibility integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure ─────────────────────────────────────────────────────────────

test('enforcesSomething separates a rule from a record', () => {
  assert.equal(enforcesSomething(`raise exception 'taken';`), true);
  assert.equal(enforcesSomething(`RAISE EXCEPTION 'nope';`), true);
  assert.equal(enforcesSomething(`if x then return null; end if;`), true);
  // The trigger every schema has, and which must never be reported.
  assert.equal(enforcesSomething(`begin new.updated_at = now(); return new; end;`), false);
  assert.equal(enforcesSomething(`begin new.user_id = auth.uid(); return new; end;`), false);
});

test('tablesRead matches on word boundaries, not substrings', () => {
  const rls = ['public.profiles', 'public.orders'];
  assert.deepEqual(tablesRead('select 1 from profiles where x', rls), ['public.profiles']);
  assert.deepEqual(tablesRead('select 1 from profiles_archive', rls), []);
  assert.deepEqual(tablesRead('nothing here', rls), []);
});

test('the fix names the constraint alternative AND pins search_path with it', () => {
  const v = classifyTrigger({
    trigger: { schema: 'public', table: 'profiles', trigger: 't_username', function: 'check_username' },
    hidden: [{ table: 'public.profiles', visible: 1, total: 9 }],
    role: 'authenticated',
  });
  assert.match(v.fix, /SECURITY DEFINER/);
  assert.match(v.fix, /SET search_path/); // a definer fix without one is the next bug
  assert.match(v.fix, /CREATE UNIQUE INDEX/);
  assert.match(v.message, /1 of 9 rows visible/);
});

if (PGlite) {
  async function fresh({ definer = '', extra = '' } = {}) {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table profiles (id serial primary key, user_id text, username text, updated_at timestamptz);
      insert into profiles (user_id, username) values ('u_other', 'taken');
      alter table profiles enable row level security;
      create policy own on profiles for all to authenticated
        using (user_id = current_setting('app.uid', true))
        with check (user_id = current_setting('app.uid', true));
      grant select, insert on profiles to authenticated;
      grant usage on sequence profiles_id_seq to authenticated;

      create function check_username() returns trigger language plpgsql ${definer}
      as $fn$
        begin
          if exists (select 1 from profiles where username = new.username) then
            raise exception 'username taken';
          end if;
          return new;
        end;
      $fn$;
      create trigger t_username before insert on profiles
        for each row execute function check_username();
      ${extra}
    `);
    return {
      db,
      query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined),
      config: { role: 'authenticated' },
    };
  }

  async function insertAs(db, uid, username) {
    await db.query('begin');
    let out;
    try {
      await db.query(`select set_config('app.uid', $1, true)`, [uid]);
      await db.query('set local role authenticated');
      await db.query(`insert into profiles (user_id, username) values ($1, $2)`, [uid, username]);
      out = 'inserted';
    } catch (e) { out = `blocked: ${e.message}`; }
    await db.query('rollback');
    return out;
  }

  test('DEMONSTRATES it: the duplicate is INSERTED, not merely unreported', async () => {
    const { db } = await fresh();
    assert.equal(await insertAs(db, 'u_me', 'taken'), 'inserted');
  });

  test('…and SECURITY DEFINER is what makes the same trigger work', async () => {
    const { db } = await fresh({ definer: 'security definer' });
    assert.match(await insertAs(db, 'u_me', 'taken'), /blocked/);
  });

  test('CATCHES it', async () => {
    const { query, config } = await fresh();
    const res = await check({ query, config });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations[0].kind, 'trigger-reads-hidden-rows');
    assert.match(res.violations[0].where, /t_username/);
  });

  test('a SECURITY DEFINER trigger is not reported — it already sees everything', async () => {
    const { query, config } = await fresh({ definer: 'security definer' });
    const res = await check({ query, config });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('a trigger that RECORDS rather than enforces is never reported', async () => {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table profiles (id serial primary key, user_id text, updated_at timestamptz);
      insert into profiles (user_id) values ('u_other');
      alter table profiles enable row level security;
      create policy own on profiles for all to authenticated
        using (user_id = current_setting('app.uid', true));
      grant select, insert on profiles to authenticated;
      -- the trigger every schema has
      create function touch() returns trigger language plpgsql
      as $fn$ begin new.updated_at = now(); return new; end; $fn$;
      create trigger t_touch before update on profiles for each row execute function touch();
    `);
    const res = await check({
      query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined),
      config: { role: 'authenticated' },
    });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('when the role can see every row it is a NOTE, not a failure', async () => {
    // Nothing is being missed today; the point is that one narrowing policy
    // turns this into a silent failure, and that is worth knowing in advance.
    const { db, query } = await fresh();
    await db.exec(`drop policy own on profiles;
                   create policy all_rows on profiles for all to authenticated using (true) with check (true);`);
    const res = await check({ query, config: { role: 'authenticated' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.ok(res.notes.some((n) => /t_username/.test(n.where) && /starts passing silently/.test(n.message)));
  });

  test('an allowlisted trigger is not reported', async () => {
    const { query } = await fresh();
    const res = await check({ query, config: { role: 'authenticated', allowlist: ['t_username'] } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('a database with no RLS at all skips — a skip is not a pass', async () => {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table t (id int);
      create function f() returns trigger language plpgsql as $fn$ begin raise exception 'x'; end; $fn$;
      create trigger tr before insert on t for each row execute function f();
    `);
    const res = await check({ query: (q, v) => db.query(q, Array.isArray(v) && v.length ? v : undefined) });
    assert.equal(res.skipped, true);
    assert.match(res.reason, /no RLS-protected tables/);
  });

  test('the check leaves the data alone', async () => {
    const { db, query, config } = await fresh();
    await check({ query, config });
    const rows = await db.query('select count(*)::int as n from profiles');
    assert.equal(rows.rows[0].n, 1);
  });
}
