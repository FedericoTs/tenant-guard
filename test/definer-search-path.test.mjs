/**
 * A pinned `search_path` is not automatically a safe one.
 *
 * `searchPathPinned` matched `/^search_path=/` and called it done, so a function
 * pinned `SET search_path = public, app` — on a database where a lower-privileged
 * role can create in `public` — was reported as protected. It is not. The first
 * test below is the demonstration rather than an assertion about the guard: the
 * function returns the attacker's planted table.
 *
 * Also recorded here: plan caching. plpgsql caches a resolved plan per session,
 * so a function already called in that session keeps resolving to the real
 * object. The hijack is deterministic in a fresh session and a race in a warm
 * one — and PostgREST/pgbouncer sessions turn over constantly, so "warm" is not
 * a defence. Worth pinning as a test so nobody later reads a lucky green run as
 * evidence the pin held.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { searchPathSchemas, shadowableSchemas, searchPathPinned } from '../src/guards/definer-rpc.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('definer search_path integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure ─────────────────────────────────────────────────────────────

test('searchPathSchemas splits the clause proconfig actually stores', () => {
  assert.deepEqual(searchPathSchemas(['search_path=public, app']), ['public', 'app']);
  assert.deepEqual(searchPathSchemas(['search_path="my schema", public']), ['my schema', 'public']);
  assert.deepEqual(searchPathSchemas(['statement_timeout=5s']), []);
  assert.deepEqual(searchPathSchemas(null), []);
});

test('searchPathSchemas drops $user — it is not a name that can be checked', () => {
  assert.deepEqual(searchPathSchemas(['search_path=$user, public']), ['public']);
});

test('shadowableSchemas: a pin to a WRITABLE schema protects nothing', () => {
  assert.deepEqual(shadowableSchemas(['search_path=public, app'], ['public']), ['public']);
});

test('shadowableSchemas: ORDER decides it', () => {
  // Resolution stops being hijackable at the first schema they cannot plant in.
  assert.deepEqual(shadowableSchemas(['search_path=app, public'], ['public']), []);
  assert.deepEqual(shadowableSchemas(['search_path=pg_catalog, public'], ['public']), []);
});

test('shadowableSchemas: a role that can create nowhere shadows nothing', () => {
  assert.deepEqual(shadowableSchemas(['search_path=public, app'], []), []);
});

test('searchPathPinned still answers its own narrower question', () => {
  // Kept, because "is there a SET clause at all" is still what the note needs.
  assert.equal(searchPathPinned(['search_path=public']), true);
  assert.equal(searchPathPinned([]), false);
});

if (PGlite) {
  async function hijackTrial({ pin, callFirst = false }) {
    const db = new PGlite();
    await db.exec(`
      create role attacker nologin;
      create schema app;
      grant usage on schema app to attacker;
      grant usage, create on schema public to attacker;
      create table app.real_lookup (v text);
      insert into app.real_lookup values ('legit');
      create function app.f() returns text
        language plpgsql security definer
        ${pin}
      as $fn$
        declare r text;
        begin select v into r from real_lookup limit 1; return r; end;
      $fn$;
      grant execute on function app.f() to attacker;
    `);
    if (callFirst) await db.query('select app.f()'); // warms the plpgsql plan cache
    let out;
    await db.query('begin');
    await db.query('set local role attacker');
    await db.query('create table public.real_lookup (v text)');
    await db.query(`insert into public.real_lookup values ('HIJACKED')`);
    try { out = (await db.query('select app.f() as o')).rows[0].o; }
    catch (e) { out = `ERROR ${e.code}`; }
    await db.query('rollback');
    return out;
  }

  test('DEMONSTRATES it: pinned to a writable schema, the definer runs the attacker\'s table', async () => {
    assert.equal(await hijackTrial({ pin: 'set search_path = public, app' }), 'HIJACKED');
  });

  test('…pinning the owner\'s schema FIRST is what actually stops it', async () => {
    assert.equal(await hijackTrial({ pin: 'set search_path = app, public' }), 'legit');
  });

  test('…and no pin at all is hijacked, as expected', async () => {
    assert.equal(await hijackTrial({ pin: '' }), 'HIJACKED');
  });

  test('plan caching hides it in a WARM session — which is not a defence', async () => {
    // Same broken pin, one prior call in the session: the cached plan still
    // resolves to the real table. A green result here would be luck, not safety.
    assert.equal(await hijackTrial({ pin: 'set search_path = public, app', callFirst: true }), 'legit');
  });
}
