/**
 * `pg_temp` — the hole in the advice this tool used to print.
 *
 * 0.32.0 correctly worked out that a pin to a WRITABLE schema is not a pin, and
 * then recommended `SET search_path = pg_catalog, <schema>`. That recommendation
 * is defeated, because **Postgres searches `pg_temp` before every schema you
 * list unless you name it explicitly**, and `TEMP` on the database is granted to
 * `PUBLIC` by default in every Postgres version. So the attacker needs no CREATE
 * privilege anywhere — just the ability to open a session.
 *
 * Found by fact-checking the claim before publishing it, which is the only
 * reason it was caught: the guard's own tests all asserted the wrong pin was
 * correct, so the suite was green and agreed with itself.
 *
 * Measured, with `CREATE ON SCHEMA public` revoked from PUBLIC:
 *
 *     pg_catalog, app              -> TEMP-HIJACKED
 *     pg_catalog, app, pg_temp     -> legit
 *     ''  (unqualified body)       -> the function BREAKS
 *     ''  (qualified body)         -> legit
 *
 * The last two rows are why the fix text recommends naming `pg_temp` rather than
 * `search_path = ''`: the strict form is only safe if you also rewrite the body,
 * and a linter's fix has to be safe to apply without thinking.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { temporarilyShadowable } from '../src/guards/definer-rpc.mjs';
import { omitsTempSchema, findUnpinnedDefiners } from '../src/guards/definer-grants.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('pg_temp shadowing (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure ─────────────────────────────────────────────────────────────

test('temporarilyShadowable: a pin that omits pg_temp is incomplete', () => {
  assert.equal(temporarilyShadowable(['search_path=pg_catalog, app']), true);
  assert.equal(temporarilyShadowable(['search_path=pg_catalog, app, pg_temp']), false);
  assert.equal(temporarilyShadowable(['search_path=app, pg_temp, public']), false);
  // unpinned is a separate, louder finding — this one must not double-report it
  assert.equal(temporarilyShadowable([]), false);
  assert.equal(temporarilyShadowable(null), false);
});

test('omitsTempSchema agrees, statically', () => {
  assert.equal(omitsTempSchema(['pg_catalog', 'app']), true);
  assert.equal(omitsTempSchema(['pg_catalog', 'app', 'pg_temp']), false);
  assert.equal(omitsTempSchema(['PG_TEMP']), false); // case-insensitive
  assert.equal(omitsTempSchema([]), false);
});

test('the static guard files it in its own bucket, not as "correctly pinned"', () => {
  const sql = `
    create function f() returns text language plpgsql security definer
      set search_path = pg_catalog, app
    as $fn$ begin return (select v from lookup limit 1); end; $fn$;`;
  const r = findUnpinnedDefiners([{ name: '001.sql', sql }]);
  assert.deepEqual(r.noTemp.map((f) => f.name), ['f']);
  assert.deepEqual(r.pinned, []);
});

if (PGlite) {
  async function hijack(pin, { qualifiedBody = false } = {}) {
    const db = new PGlite();
    const ref = qualifiedBody ? 'app.real_lookup' : 'real_lookup';
    await db.exec(`
      create role attacker nologin;
      create schema app;
      grant usage on schema app to attacker;
      create table app.real_lookup (v text);
      insert into app.real_lookup values ('legit');
      create function app.f() returns text language plpgsql security definer
        ${pin}
      as $fn$ declare r text; begin select v into r from ${ref} limit 1; return r; end; $fn$;
      grant execute on function app.f() to attacker;
      -- the attacker has nowhere to plant except pg_temp
      revoke create on schema public from public;
    `);
    let out;
    await db.query('begin');
    try {
      await db.query('set local role attacker');
      await db.query('create temp table real_lookup (v text)');
      await db.query(`insert into real_lookup values ('TEMP-HIJACKED')`);
      out = (await db.query('select app.f() as o')).rows[0].o;
    } catch (e) { out = `ERROR ${e.code}`; }
    await db.query('rollback');
    return out;
  }

  test('DEMONSTRATES it: the pin this tool used to recommend is hijacked by a TEMP table', async () => {
    assert.equal(await hijack('set search_path = pg_catalog, app'), 'TEMP-HIJACKED');
  });

  test('…and naming pg_temp last is what actually stops it', async () => {
    assert.equal(await hijack('set search_path = pg_catalog, app, pg_temp'), 'legit');
  });

  test("search_path = '' BREAKS an unqualified body — which is why it is not the blind fix", async () => {
    const out = await hijack("set search_path = ''");
    assert.match(String(out), /ERROR|TEMP-HIJACKED/);
  });

  test("…it only works once the body is schema-qualified", async () => {
    assert.equal(await hijack("set search_path = ''", { qualifiedBody: true }), 'legit');
  });

  test('the attacker needs no CREATE privilege anywhere — TEMP is granted to PUBLIC', async () => {
    // Proving the precondition rather than assuming it: with CREATE revoked, a
    // plant into public fails, and the temp route still succeeds.
    const db = new PGlite();
    await db.exec(`
      create role attacker nologin;
      revoke create on schema public from public;
    `);
    await db.query('begin');
    await db.query('set local role attacker');
    // Savepoints between the two: the first statement is EXPECTED to fail, and a
    // failed statement aborts the transaction, so the second would never run.
    const attempt = async (sql) => {
      await db.query('savepoint s');
      try { await db.query(sql); await db.query('release savepoint s'); return 'allowed'; }
      catch (e) { await db.query('rollback to savepoint s'); return e.code; }
    };
    const planted = await attempt('create table public.x (i int)');
    const temped = await attempt('create temp table y (i int)');
    await db.query('rollback');
    assert.equal(planted, '42501', 'CREATE on public is genuinely revoked');
    assert.equal(temped, 'allowed', 'TEMP is granted to PUBLIC by default');
  });
}
