/**
 * Audit regressions for create-grants.
 *
 * Two shipped defects, both in the "wrong advice" class rather than the "missed
 * violation" class — the guard failed the build correctly and then told the
 * reader something untrue about what to do next.
 *
 *   1. The exploitability sentence was decided by `searchPathPinned()`, which
 *      only tests whether a `SET search_path` clause EXISTS. Measured on PGlite
 *      (PG 18.3): a definer function pinned `= public, app` reading `secrets`
 *      unqualified with the real table in `app`, `CREATE ON SCHEMA public`
 *      granted to `anon`. As anon, `create table public.secrets(id int)` then
 *      `select public.get_notice()` returned the planted table (1 row) rather
 *      than the real one (2 rows) — a working hijack, described by the guard as
 *      "nothing is exploitable today".
 *
 *   2. The fix was always `REVOKE … FROM <role>`, which is a silent no-op for a
 *      privilege held by role membership. Measured: `grant create on schema
 *      public to app_writer; grant app_writer to anon` — the emitted REVOKE ran
 *      clean and `has_schema_privilege('anon','public','CREATE')` was true
 *      before and true after.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  classifyCreateGrant,
  pinnedThroughWritable,
  armingDefiners,
  schemaCreateGrantsSql,
  databaseCreateGrantsSql,
  writableSchemasSql,
} from '../src/guards/create-grants.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('create-grants audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure: a pin through a writable schema is not a pin ────────────────

test('pinnedThroughWritable: a writable schema AHEAD of the rest of the path is reported', () => {
  // The measured hijack: pinned `public, app`, table in app, public writable.
  assert.deepEqual(pinnedThroughWritable(['search_path=public, app'], ['public']), ['public']);
});

test('pinnedThroughWritable: order matters — the same two schemas the other way round are safe', () => {
  // Resolution reaches `app` first, and the attacker cannot plant there.
  assert.deepEqual(pinnedThroughWritable(['search_path=app, public'], ['public']), []);
});

test('pinnedThroughWritable: the LAST entry can never be shadowed — nothing follows it', () => {
  assert.deepEqual(pinnedThroughWritable(['search_path=public'], ['public']), []);
  assert.deepEqual(pinnedThroughWritable(['search_path=pg_catalog, public'], ['public']), []);
});

test('pinnedThroughWritable: pg_catalog does not stop the walk — it holds no user tables', () => {
  assert.deepEqual(pinnedThroughWritable(['search_path=pg_catalog, public, app'], ['public']), ['public']);
});

test('pinnedThroughWritable: a schema the role cannot plant in stops the walk', () => {
  // `locked` may itself hold the object, and resolution stops at the first
  // schema that has it, so nothing after it can be shadowed.
  assert.deepEqual(pinnedThroughWritable(['search_path=locked, public, app'], ['public']), []);
});

test('pinnedThroughWritable: search_path = \'\' is the strictest pin, not an armed one', () => {
  assert.deepEqual(pinnedThroughWritable(["search_path="], ['public']), []);
});

test('pinnedThroughWritable: says nothing about a missing pg_temp — that grant is not the enabler', () => {
  // TEMP is granted to PUBLIC by default, so revoking CREATE fixes nothing
  // there. Claiming it here would hand the reader a REVOKE that leaves them
  // exploitable. definer-rpc owns that case.
  assert.deepEqual(pinnedThroughWritable(['search_path=pg_catalog, app'], []), []);
});

test('armingDefiners: splits unpinned (conclusive) from pinned-but-reachable (conditional)', () => {
  const rows = [
    { schema: 'public', name: 'risky', config: null },
    { schema: 'public', name: 'fake_pin', config: ['search_path=public, app'] },
    { schema: 'public', name: 'real_pin', config: ['search_path=pg_catalog, public'] },
  ];
  const a = armingDefiners(rows, ['public']);
  assert.deepEqual(a.unpinned, ['public.risky']);
  assert.deepEqual(a.shadowable.map((s) => s.fn), ['public.fake_pin']);
  assert.deepEqual(a.shadowable[0].through, ['public']);
  assert.deepEqual(a.shadowable[0].after, ['app']);
  assert.equal(a.total, 3);
});

test('armingDefiners is PER ROLE — the same pin is worthless to one role and solid against another', () => {
  const rows = [{ schema: 'public', name: 'fn', config: ['search_path=public, app'] }];
  assert.equal(armingDefiners(rows, ['public']).shadowable.length, 1);
  assert.equal(armingDefiners(rows, []).shadowable.length, 0);
});

// ── pure: the sentence itself ────────────────────────────────────────

const base = { scope: 'schema', where: 'public', unauthenticatedRoles: ['anon'], appRole: 'authenticated', scannedSchemas: ['public'] };

test('a pin through a writable schema is NOT described as "nothing is exploitable today"', () => {
  const v = classifyCreateGrant({
    ...base, role: 'anon', definerCount: 1,
    shadowable: [{ fn: 'public.get_notice', through: ['public'], after: ['app'] }],
  });
  assert.doesNotMatch(v.message, /nothing is exploitable today/);
  assert.doesNotMatch(v.message, /hijackable through this grant today/);
  assert.match(v.message, /may already work TODAY/);
  assert.match(v.message, /public\.get_notice/);
});

test('the conditional case says WHY it is conditional instead of picking a side', () => {
  const v = classifyCreateGrant({
    ...base, role: 'anon', definerCount: 1,
    shadowable: [{ fn: 'public.get_notice', through: ['public'], after: ['app'] }],
  });
  assert.match(v.message, /depends on which schema its unqualified names resolve to/);
});

test('the clean sentence is scoped to the schemas actually scanned, not to the database', () => {
  const v = classifyCreateGrant({ ...base, role: 'anon', definerCount: 0 });
  assert.match(v.message, /no SECURITY DEFINER functions in "public"/);
  assert.doesNotMatch(v.message, /nothing is exploitable today/);
});

test('a skip is never a pass: an unreadable catalog is reported as unknown, not clear', () => {
  const noDefiners = classifyCreateGrant({ ...base, role: 'anon', definersKnown: false });
  assert.match(noDefiners.message, /could not read/);
  assert.doesNotMatch(noDefiners.message, /hijackable through this grant today/);

  const noWritable = classifyCreateGrant({ ...base, role: 'anon', definerCount: 2, writableKnown: false });
  assert.match(noWritable.message, /could not read which schemas/);
  assert.doesNotMatch(noWritable.message, /none of them is hijackable/);
});

// ── pure: the fix is resolved to the provenance of the privilege ─────

test('an INHERITED privilege never gets the REVOKE that does nothing', () => {
  const v = classifyCreateGrant({
    ...base, role: 'anon', direct: false,
    viaMemberships: ['app_writer'], grantHolders: ['app_writer'],
  });
  assert.match(v.fix, /has NO grant of its own/);
  assert.match(v.fix, /REVOKE app_writer FROM anon;/);
  assert.match(v.fix, /REVOKE CREATE ON SCHEMA public FROM app_writer;/);
  // The dead-end command may be NAMED as a no-op, but never offered as the fix.
  assert.doesNotMatch(v.fix.split('Narrower fix')[0], /^REVOKE CREATE ON SCHEMA public FROM anon;/m);
});

test('the membership revoke names the DIRECT edge, because membership is transitive', () => {
  // `grant r_top to r_mid; grant r_mid to anon` — anon is NOT a member of
  // r_top, so `REVOKE r_top FROM anon` would itself be a no-op.
  const v = classifyCreateGrant({
    ...base, role: 'anon', viaMemberships: ['r_mid'], grantHolders: ['r_top'],
  });
  assert.match(v.fix, /REVOKE r_mid FROM anon;/);
  assert.doesNotMatch(v.fix, /REVOKE r_top FROM anon;/);
  assert.match(v.fix, /REVOKE CREATE ON SCHEMA public FROM r_top;/);
  assert.match(v.fix, /affects EVERY member/); // blast radius stated
});

test('OWNERSHIP carries CREATE implicitly, so REVOKE is named as the no-op it is', () => {
  const v = classifyCreateGrant({ ...base, role: 'anon', isOwner: true });
  assert.match(v.fix, /OWNS schema public/);
  assert.match(v.fix, /would succeed and change nothing/);
  assert.match(v.fix, /ALTER SCHEMA public OWNER TO/);
});

test('a SUPERUSER passes every privilege check, and the fix says so', () => {
  const v = classifyCreateGrant({ ...base, role: 'admin', isSuper: true });
  assert.match(v.fix, /SUPERUSER/);
  assert.match(v.fix, /would succeed and change nothing/);
});

test('a DIRECT grant still gets the plain REVOKE — the correct case must not regress', () => {
  const v = classifyCreateGrant({ ...base, role: 'anon', direct: true });
  assert.match(v.fix, /^REVOKE CREATE ON SCHEMA public FROM anon;/);
  assert.doesNotMatch(v.fix, /NO grant of its own/);
});

test('an unresolvable provenance refuses to print a REVOKE as if it would work', () => {
  const v = classifyCreateGrant({ ...base, role: 'anon' }); // effective, but no source
  assert.match(v.fix, /could not find where this privilege comes from/);
  assert.match(v.fix, /Do not assume/);
});

test('the database fix names the real database instead of a placeholder that will not run', () => {
  const v = classifyCreateGrant({ ...base, scope: 'database', where: undefined, role: 'anon', direct: true, databaseName: 'appdb' });
  assert.match(v.fix, /REVOKE CREATE ON DATABASE appdb FROM anon;/);
  assert.doesNotMatch(v.fix, /<your database>/);
});

test('identifiers that need quoting get quoted, so the emitted SQL parses', () => {
  const v = classifyCreateGrant({ ...base, where: 'My Schema', role: 'App Writer', direct: true });
  assert.match(v.fix, /REVOKE CREATE ON SCHEMA "My Schema" FROM "App Writer";/);
});

// ── SQL shape ────────────────────────────────────────────────────────

test('the schema query reads the provenance of the privilege, not just its existence', () => {
  const { text } = schemaCreateGrantsSql(['anon'], ['public']);
  assert.match(text, /as via_memberships/);
  assert.match(text, /as grant_holders/);
  assert.match(text, /as is_owner/);
  assert.match(text, /as is_super/);
  // pg_has_role(…, 'USAGE') and not pg_auth_members alone: a NOINHERIT member
  // does not get the privilege, and has_schema_privilege agrees.
  assert.match(text, /pg_has_role\(r\.oid, g\.oid, 'USAGE'\)/);
});

test('the database query gained the same provenance columns and the database name', () => {
  const { text } = databaseCreateGrantsSql(['anon']);
  assert.match(text, /d\.datname as database/);
  assert.match(text, /as direct_can_create/);
  assert.match(text, /as via_memberships/);
  assert.match(text, /d\.datdba = r\.oid/);
});

test('writableSchemasSql looks at EVERY schema, because a pin can name one outside the audit', () => {
  const { text, values } = writableSchemasSql(['anon']);
  assert.doesNotMatch(text, /nspname = any\(\$2\)/);
  assert.match(text, /has_schema_privilege/);
  assert.match(text, /grantee = 0/);          // the PUBLIC row
  assert.deepEqual(values, [['anon']]);
});

// ── against a real database ──────────────────────────────────────────

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
  test('a LIVE hijack through a pinned path is not reported as a future risk', async () => {
    const { db, query } = await freshDb(`
      create schema app;
      grant usage on schema app to anon;
      create table app.secrets(id int);
      insert into app.secrets values (1),(2);
      create function public.get_notice() returns int language sql security definer
        set search_path = public, app as $$ select count(*)::int from secrets $$;
      grant execute on function public.get_notice() to anon;
      grant create on schema public to anon;
    `);

    const res = await check({ query });
    const v = res.violations.find((x) => x.where === 'public:anon');
    assert.ok(v, JSON.stringify(res, null, 2));
    assert.doesNotMatch(v.message, /nothing is exploitable today/);
    assert.match(v.message, /public\.get_notice/);
    assert.match(v.message, /may already work TODAY/);

    // …and the hijack really does work at this exact moment.
    await db.exec(`set role anon; create table public.secrets(id int); insert into public.secrets values (9);`);
    const hijacked = (await db.query('select public.get_notice() as n')).rows[0].n;
    await db.exec('reset role');
    assert.equal(hijacked, 1, 'expected the planted table (1 row), not app.secrets (2 rows)');
    await db.close();
  });

  test('the emitted fix for an INHERITED grant actually removes the privilege', async () => {
    const { db, query } = await freshDb(`
      create role app_writer nologin;
      grant create on schema public to app_writer;
      grant app_writer to anon;
    `);
    const before = (await db.query(`select has_schema_privilege('anon','public','CREATE') as p`)).rows[0].p;
    assert.equal(before, true);

    const res = await check({ query });
    const v = res.violations.find((x) => x.where === 'public:anon');
    assert.equal(v.kind, 'anon-create');
    assert.match(v.fix, /REVOKE app_writer FROM anon;/);

    // Apply the narrower fix exactly as printed.
    await db.exec('REVOKE app_writer FROM anon;');
    const after = (await db.query(`select has_schema_privilege('anon','public','CREATE') as p`)).rows[0].p;
    assert.equal(after, false, 'the printed fix must actually remove the privilege');
    assert.equal((await check({ query })).ok, true, 'and the guard must go green afterwards');
    await db.close();
  });

  test('the WIDER fix works too, and is labelled with its blast radius', async () => {
    const { db, query } = await freshDb(`
      create role r_top nologin; grant create on schema public to r_top;
      create role r_mid nologin; grant r_top to r_mid; grant r_mid to anon;
    `);
    const v = (await check({ query })).violations.find((x) => x.where === 'public:anon');
    assert.match(v.fix, /REVOKE r_mid FROM anon;/);          // the direct edge
    assert.match(v.fix, /REVOKE CREATE ON SCHEMA public FROM r_top;/); // the source
    assert.match(v.fix, /do not apply it blind if that is your migration role/);

    await db.exec('REVOKE CREATE ON SCHEMA public FROM r_top;');
    assert.equal((await db.query(`select has_schema_privilege('anon','public','CREATE') as p`)).rows[0].p, false);
    assert.equal((await check({ query })).ok, true);
    await db.close();
  });

  test('ownership is detected against a real catalog, where it is NOT in the ACL', async () => {
    const { db, query } = await freshDb('create schema owned authorization anon;');
    const res = await check({ query, config: { schemas: ['public', 'owned'] } });
    const v = res.violations.find((x) => x.where === 'owned:anon');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.fix, /OWNS schema owned/);
    assert.match(v.fix, /ALTER SCHEMA owned OWNER TO/);
    await db.close();
  });

  test('CALIBRATION: a pin the role cannot plant ahead of stays quiet, even with CREATE held', async () => {
    // The whole point of the guard is that this must not become a cry-wolf.
    const { db, query } = await freshDb(`
      create function public.safe() returns int language sql security definer
        set search_path = pg_catalog, public as $$ select 1 $$;
      grant create on schema public to anon;
    `);
    const v = (await check({ query })).violations.find((x) => x.where === 'public:anon');
    assert.match(v.message, /none of them is hijackable through this grant today/);
    assert.doesNotMatch(v.message, /may already work TODAY/);
    await db.close();
  });

  test('CALIBRATION: the same pinned function is harmless to a role that cannot CREATE', async () => {
    const { db, query } = await freshDb(`
      create schema app;
      create table app.secrets(id int);
      create function public.get_notice() returns int language sql security definer
        set search_path = public, app as $$ select count(*)::int from secrets $$;
      grant create on schema public to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, 'the app role holding CREATE is a note, not a failure');
    assert.equal(res.violations.length, 0, JSON.stringify(res.violations, null, 2));
    // anon cannot plant anywhere, so nothing is said about anon at all.
    assert.equal(res.notes.filter((n) => n.where === 'public:anon').length, 0);
    await db.close();
  });
}
