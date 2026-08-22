/**
 * create-grants against a real database.
 *
 * The first test is the point: a `CREATE` grant with no SECURITY DEFINER
 * function anywhere is invisible to every other guard here — `definer-rpc` has
 * nothing to evaluate — and it is exactly the state that arms the next definer
 * function somebody writes without `SET search_path`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check } from '../src/guards/create-grants.mjs';
import { check as checkDefinerRpc } from '../src/guards/definer-rpc.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('create-grants integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function freshDb(setup = '') {
  const db = new PGlite();
  await db.exec(`
    create role anon nologin;
    create role authenticated nologin;
    grant usage on schema public to anon, authenticated;
    revoke create on schema public from public;
  `);
  if (setup) await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('CATCHES the latent grant that no other guard can see', async () => {
    // anon can create, and there is NO definer function at all — so definer-rpc
    // has nothing to evaluate and reports clean. The precondition is still armed.
    const { query } = await freshDb('grant create on schema public to anon;');

    const rpc = await checkDefinerRpc({ query });
    assert.equal(rpc.violations.length, 0, 'definer-rpc has no function to flag');

    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'public:anon');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.kind, 'anon-create');
    // Scoped to what was scanned. The old wording ("nothing is exploitable
    // today") asserted global safety off the back of a presence-only pin check.
    assert.match(v.message, /no SECURITY DEFINER functions in "public"/);
    assert.match(v.message, /nothing there is hijackable through this grant today/);
    assert.match(v.message, /arms the next one/);
  });

  test('with an unpinned definer present it says exploitable NOW and points at the other guard', async () => {
    const { query } = await freshDb(`
      grant create on schema public to anon;
      create function public.risky() returns int language sql security definer as $$ select 1 $$;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false);
    const v = res.violations.find((x) => x.where === 'public:anon');
    assert.match(v.message, /exploitable NOW/);
    assert.match(v.message, /public\.risky/);
    assert.match(v.message, /tenant-guard rpc/);
  });

  test('a PINNED definer is not counted as armed', async () => {
    // `pg_catalog, public` with the function and its objects in `public`:
    // nothing anon can plant in comes BEFORE where the name resolves, so the
    // pin genuinely holds. This is the calibration case — it must stay quiet.
    const { query } = await freshDb(`
      grant create on schema public to anon;
      create function public.safe() returns int language sql security definer
        set search_path = pg_catalog, public as $$ select 1 $$;
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => x.where === 'public:anon');
    assert.match(v.message, /none of them is hijackable through this grant today/);
    assert.doesNotMatch(v.message, /may already work TODAY/);
  });

  test('CATCHES a grant to PUBLIC as one finding about the schema, not one per role', async () => {
    const { query } = await freshDb('grant create on schema public to public;');
    const res = await check({ query });
    assert.equal(res.ok, false);
    const pub = res.violations.filter((v) => v.kind === 'public-create');
    assert.equal(pub.length, 1, 'PUBLIC is one grant, so it must be one finding');
    assert.equal(pub[0].where, 'public:PUBLIC');
    // …and the per-role findings must NOT also fire for the same grant.
    assert.equal(res.violations.filter((v) => v.kind === 'anon-create').length, 0);
  });

  test('the app role holding CREATE is a NOTE, not a build failure', async () => {
    const { query } = await freshDb('grant create on schema public to authenticated;');
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.ok(res.notes.some((n) => n.where === 'public:authenticated'));
  });

  test('PASSES when nobody but the owner can create', async () => {
    const { query } = await freshDb();
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.ok(res.scanned > 0, 'it really did look');
  });

  test('a DIRECT grant is reported even when PUBLIC also has one — different fixes', async () => {
    // Revoking from PUBLIC would leave anon still holding its own grant, so
    // reporting only the PUBLIC finding would hand over an incomplete fix.
    const { query } = await freshDb(`
      grant create on schema public to public;
      grant create on schema public to anon;
    `);
    const res = await check({ query });
    const wheres = res.violations.map((v) => v.where).sort();
    assert.deepEqual(wheres, ['public:PUBLIC', 'public:anon']);
  });

  test('a PUBLIC-derived privilege alone is NOT also reported per role', async () => {
    const { query } = await freshDb('grant create on schema public to public;');
    const res = await check({ query });
    assert.deepEqual(res.violations.map((v) => v.where), ['public:PUBLIC']);
  });

  test('scanned counts SCHEMAS, not (schema, role) pairs', async () => {
    const { query } = await freshDb();
    const res = await check({ query });               // two roles, one schema
    assert.equal(res.scanned, 1);
    assert.match(res.summary, /on 1 schema\(s\)/);
  });

  test('a schema outside the configured list is never queried', async () => {
    const { query } = await freshDb(`
      create schema other;
      grant create on schema other to anon;
    `);
    const res = await check({ query, config: { schemas: ['public'] } });
    assert.equal(res.ok, true);
    assert.equal(res.violations.length, 0);
    assert.equal(res.scanned, 1);
  });

  test('an allowlisted grant is not reported', async () => {
    const { query } = await freshDb('grant create on schema public to anon;');
    const res = await check({ query, config: { allowlist: ['public:anon'] } });
    assert.equal(res.ok, true);
  });

  test('a configured role that does not exist is skipped, not an error', async () => {
    const { query } = await freshDb();
    const res = await check({ query, config: { unauthenticatedRoles: ['ghost_role'] } });
    assert.equal(res.ok, true); // has_schema_privilege on a missing role would have thrown
  });
}
