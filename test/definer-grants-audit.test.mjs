/**
 * Audit regressions for definer-grants.
 *
 * Two shipped defects.
 *
 *   1. WRONG ADVICE. The `publicFirst` and `unpinned` notes emitted a hardcoded
 *      `SET search_path = pg_catalog, public, pg_temp` that ignored the pin the
 *      author had actually written, and every ALTER/REVOKE hardcoded a `public.`
 *      schema qualifier even though `extractFunctionDefs` had thrown the real
 *      schema away. Measured on PGlite (PG 18.3), function pinned
 *      `= public, app` with its table in `app`:
 *
 *        select public.get_stuff();                                -> REAL
 *        -- the literal advice:
 *        ALTER FUNCTION public.get_stuff()
 *          SET search_path = pg_catalog, public, pg_temp;
 *        select public.get_stuff();   (attacker's public.thing absent) -> 42P01
 *        select public.get_stuff();   (attacker's public.thing present) -> PLANTED
 *
 *      So the advice either broke the function or handed it to the attacker —
 *      the exact failure the note claims to prevent. And for a function created
 *      as `app.get_priv`, both the emitted ALTER and the emitted REVOKE came
 *      back 42883 function public.get_priv() does not exist, so the advice did
 *      nothing at all.
 *
 *      Fixed by building the path FROM `fn.searchPath` (preserve every entry,
 *      pg_catalog first, public moved behind the schemas it reads, pg_temp
 *      last) and by naming the function the way its CREATE named it.
 *
 *   2. QUADRATIC SCAN. The revoked-name set was built as names x files, and
 *      `revokesAnonExecute` lowercases the whole file on every call — a
 *      204-file / 90-name corpus did 18,360 whole-file lowercasings, and that
 *      one loop was the majority of the guard's runtime. Fixed by a pure hoist
 *      (lower once, skip files with no `revoke` substring) with the matcher
 *      left completely alone, because a name-harvesting rewrite would turn any
 *      name form it missed into the guard firing on a migration that DID
 *      revoke.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  run,
  hardenedSearchPath,
  renderSearchPath,
  extractFunctionDefs,
  findDefinerGrantViolations,
  findUnpinnedDefiners,
} from '../src/guards/definer-grants.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('definer-grants audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

function withMigrations(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-dga-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const noteFor = (res, name) => res.notes.find((n) => n.message.includes(`"${name}"`));

// ── 1a. the path is built from the pin, not from a constant ──────────

test('hardenedSearchPath keeps every schema the author named', () => {
  // Dropping `app` is what turned a working function into 42P01.
  assert.deepEqual(hardenedSearchPath(['public', 'app']), ['pg_catalog', 'app', 'public', 'pg_temp']);
  assert.deepEqual(hardenedSearchPath(['public', 'app', 'billing']),
    ['pg_catalog', 'app', 'billing', 'public', 'pg_temp']);
});

test('hardenedSearchPath puts pg_catalog first, public behind the rest, pg_temp last', () => {
  assert.deepEqual(hardenedSearchPath(['public']), ['pg_catalog', 'public', 'pg_temp']);
  // Already-present entries are moved, never duplicated.
  assert.deepEqual(hardenedSearchPath(['pg_temp', 'public', 'pg_catalog', 'app']),
    ['pg_catalog', 'app', 'public', 'pg_temp']);
  assert.deepEqual(hardenedSearchPath(['app', 'APP', 'public']),
    ['pg_catalog', 'app', 'public', 'pg_temp']);
});

test('renderSearchPath quotes what needs quoting and leaves plain words alone', () => {
  // `SET search_path = pg_catalog, $user, public` is a syntax error; quoting
  // `App` would change what it resolves to, so a plain word is emitted as-is.
  assert.equal(renderSearchPath(hardenedSearchPath(['public', '$user'])),
    'pg_catalog, "$user", public, pg_temp');
  assert.equal(renderSearchPath(['my schema', 'App', 'app']), '"my schema", App, app');
});

test('the publicFirst fix names every schema the original pin had', () => {
  const res = withMigrations({
    '100_x.sql': `
      create function public.get_stuff() returns text
        language plpgsql security definer set search_path = public, app, billing
      as $fn$ begin return (select label from thing limit 1); end; $fn$;`,
  }, (dir) => run({ dir, baseline: 0 }));

  const note = noteFor(res, 'get_stuff');
  assert.ok(note, 'expected a publicFirst note');
  // Before the fix this read `SET search_path = pg_catalog, public, pg_temp;`
  // — `app` and `billing` gone.
  assert.match(note.fix, /SET search_path = pg_catalog, app, billing, public, pg_temp;/);
  // And it has to say that moving public backwards is a change to review: with
  // the same relation name in two listed schemas the reorder silently switches
  // which one the function reads (verified).
  assert.match(note.fix, /Review before applying/);
  assert.match(note.fix, /"app", "billing"/);
});

test('a single-schema public pin gets no bogus reorder warning', () => {
  // Nothing moves relative to what it reads, so the note must not imply it does.
  // This one passed BEFORE the fix too — for a single-entry `public` pin the old
  // hardcoded string happened to be right. It is here as the calibration half:
  // the new path-building must not start warning about the case it got correct.
  const res = withMigrations({
    '100_x.sql': `
      create function public.only_public() returns text
        language plpgsql security definer set search_path = public
      as $fn$ begin return (select label from thing limit 1); end; $fn$;`,
  }, (dir) => run({ dir, baseline: 0 }));
  const note = noteFor(res, 'only_public');
  assert.match(note.fix, /SET search_path = pg_catalog, public, pg_temp;/);
  assert.doesNotMatch(note.fix, /Review before applying/);
});

// ── 1b. the advice names the function that actually exists ───────────

test('extractFunctionDefs keeps the schema the CREATE named', () => {
  const [fn] = extractFunctionDefs('create function app.get_priv() returns void as $$ begin end $$;');
  assert.equal(fn.name, 'get_priv');   // matching stays on the bare name
  assert.equal(fn.schema, 'app');
  assert.equal(fn.target, 'app.get_priv');
});

test('an UNQUALIFIED create yields an unqualified target, not a guessed public.', () => {
  // It resolved through the migration runner's search_path; the ALTER will too.
  // Guessing `public` is how the 42883 got in.
  const [fn] = extractFunctionDefs('create function bare_fn() returns void as $$ begin end $$;');
  assert.equal(fn.schema, null);
  assert.equal(fn.target, 'bare_fn');
});

test('ALTER and REVOKE advice for a non-public function names its real schema', () => {
  const res = withMigrations({
    '100_x.sql': `
      create function app.get_priv() returns text
        language plpgsql security definer
      as $fn$ begin insert into app.audit(x) values (1); return 'z'; end; $fn$;`,
  }, (dir) => run({ dir, baseline: 0 }));

  // Before the fix both of these said `public.get_priv` -> 42883.
  assert.equal(res.violations.length, 1);
  assert.match(res.violations[0].fix, /REVOKE EXECUTE ON FUNCTION app\.get_priv\(<args>\)/);
  assert.doesNotMatch(res.violations[0].fix, /public\.get_priv/);

  const note = noteFor(res, 'get_priv');
  assert.match(note.fix, /ALTER FUNCTION app\.get_priv\(<args>\)/);
  assert.doesNotMatch(note.fix, /public\.get_priv/);
});

test('the noTemp fix names the real schema and keeps the whole path', () => {
  const res = withMigrations({
    '100_x.sql': `
      create function app.no_temp() returns text
        language plpgsql security definer set search_path = pg_catalog, app
      as $fn$ begin return (select label from thing limit 1); end; $fn$;`,
  }, (dir) => run({ dir, baseline: 0 }));
  const note = noteFor(res, 'no_temp');
  assert.match(note.fix, /ALTER FUNCTION app\.no_temp\(<args>\) SET search_path = pg_catalog, app, pg_temp;/);
});

test('the REVOKE advice does not name a role that may not exist', () => {
  // `FROM PUBLIC, anon` aborts with 42704 on any non-Supabase database, so the
  // revoke never happens. PUBLIC alone is what closes it — the grant lives on
  // PUBLIC and anon inherits it, which is this guard's whole premise.
  const res = withMigrations({
    '100_x.sql': `
      create function public.wipe_org(p uuid) returns void
        language plpgsql security definer
      as $fn$ begin delete from orgs where id = p; end; $fn$;`,
  }, (dir) => run({ dir, baseline: 0 }));
  assert.match(res.violations[0].fix, /FROM PUBLIC;/);
  assert.doesNotMatch(res.violations[0].fix, /FROM PUBLIC, anon;/);
  // …but the direct-grant case must still be mentioned, not dropped.
  assert.match(res.violations[0].fix, /granted EXECUTE directly to anon/);
});

// ── 1c. the emitted SQL, executed verbatim, against a real database ──

test('every emitted statement RUNS, closes the hijack, and leaves the function working', async (t) => {
  if (!PGlite) return t.skip('pglite not installed');

  const MIG = `
    create function public.get_stuff() returns text
      language plpgsql security definer set search_path = public, app
    as $fn$ begin return (select label from thing limit 1); end; $fn$;
    create function app.no_temp() returns text
      language plpgsql security definer set search_path = pg_catalog, app
    as $fn$ begin return (select label from thing limit 1); end; $fn$;
    create function app.get_priv() returns text
      language plpgsql security definer
    as $fn$ begin insert into app.audit(x) values (1); return 'z'; end; $fn$;
  `;
  const res = withMigrations({ '100_x.sql': MIG }, (dir) => run({ dir, baseline: 0 }));

  const db = new PGlite();
  try {
    // Plant BEFORE the first call, so nothing is served from a cached plpgsql plan.
    await db.exec(`
      create schema app;
      create table app.thing(label text); insert into app.thing values ('REAL');
      create table app.audit(x int);
      create table public.thing(label text); insert into public.thing values ('PLANTED');
    `);
    await db.exec(MIG);
    await db.exec(`create temp table thing(label text); insert into pg_temp.thing values ('TEMP-PLANT');`);

    const call = async (fn) => (await db.query(`select ${fn}() as v`)).rows[0].v;

    // As shipped, both are hijacked — this is the problem being fixed.
    assert.equal(await call('public.get_stuff'), 'TEMP-PLANT');
    assert.equal(await call('app.no_temp'), 'TEMP-PLANT');

    // Nothing is retyped by hand: pull the statements out of the emitted text.
    const stmts = [];
    for (const item of [...res.violations, ...res.notes]) {
      for (const line of String(item.fix ?? '').split('\n')) {
        const m = /\b((?:ALTER|REVOKE)\b[^\n]*;)/i.exec(line);
        if (m) stmts.push(m[1].replace('(<args>)', '()'));
      }
    }
    assert.equal(stmts.length, 4, `expected 4 executable statements, got ${stmts.join(' | ')}`);
    for (const s of stmts) {
      // Before the fix this threw 42883 (public.get_priv / public.no_temp).
      await db.exec(s);
    }
    await db.exec('discard plans;');

    // The attacker's objects are all still there.
    assert.equal(await call('public.get_stuff'), 'REAL');
    assert.equal(await call('app.no_temp'), 'REAL');
    assert.equal(await call('app.get_priv'), 'z'); // still works after the revoke
    const { rows } = await db.query(
      `select has_function_privilege('public','app.get_priv()','execute') as pub`,
    );
    assert.equal(rows[0].pub, false, 'the REVOKE must actually have landed');
  } finally {
    await db.close();
  }
});

// ── 2. the revoke scan: same answers, not names x files ──────────────

test('the revoked-name scan reads each file a bounded number of times', () => {
  // Deterministic stand-in for the timing measurement: count reads of `sql`.
  // Before the hoist the revoke loop destructured `sql` once per (name, file)
  // pair, so 20 files x 40 names alone was 800 reads on top of the parse pass.
  const FILES = 20, FNS = 40;
  let reads = 0;
  const files = [];
  for (let i = 0; i < FILES; i++) {
    let sql = 'select 1;\n'.repeat(20);
    for (let j = 0; j < FNS / FILES; j++) {
      const k = i * (FNS / FILES) + j;
      sql += `create function public.fn_${k}() returns void language plpgsql security definer `
        + `as $f$ begin insert into t(a) values (1); end; $f$;\n`;
    }
    files.push({
      name: `${String(100 + i).padStart(6, '0')}_m.sql`,
      get sql() { reads++; return sql; },
    });
  }

  const v = findDefinerGrantViolations(files, { baseline: 0 });
  assert.equal(v.length, FNS, 'every function is still reported');
  assert.ok(reads <= FILES * 5, `expected <= ${FILES * 5} reads of file text, got ${reads}`);
});

test('the hoist did not change what counts as a revoke', () => {
  // Passes before AND after by design — that is the point of it. The hoist is
  // only worth having if it is semantics-free, so this pins the two forms most
  // likely to be lost by a rewrite of the matcher.
  // The matcher is name-anchored and gap-tolerant on purpose. These two forms
  // both counted before and must both still count — a name form that stops
  // being recognised means the guard fires on a migration that DID revoke.
  const multi = [
    { name: '100_a.sql', sql: `
        create function public.a(p uuid) returns void language plpgsql security definer
          as $f$ begin delete from t where id = p; end; $f$;
        create function public.b(p uuid) returns void language plpgsql security definer
          as $f$ begin delete from t where id = p; end; $f$;
        REVOKE EXECUTE ON FUNCTION public.a(uuid), public.b(uuid) FROM PUBLIC, anon;` },
  ];
  assert.deepEqual(findDefinerGrantViolations(multi, { baseline: 0 }), []);

  // A revoke that only ever appears inside a dollar-quoted EXECUTE string still
  // matched before the hoist, so it must still match now.
  const nested = [
    { name: '100_a.sql', sql: `
        create function public.c(p uuid) returns void language plpgsql security definer
          as $f$ begin delete from t where id = p; end; $f$;
        do $mig$ begin
          execute 'revoke execute on function public.c(uuid) from public';
        end $mig$;` },
  ];
  assert.deepEqual(findDefinerGrantViolations(nested, { baseline: 0 }), []);
});

test('a file with no REVOKE in it is still scanned for functions', () => {
  // The hoist skips revoke-free files only for the REVOKE scan. Skipping them
  // for the parse would be a false negative.
  const files = [
    { name: '100_a.sql', sql: `
        create function public.wipe(p uuid) returns void language plpgsql security definer
          as $f$ begin delete from t where id = p; end; $f$;` },
  ];
  const v = findDefinerGrantViolations(files, { baseline: 0 });
  assert.equal(v.length, 1);
  assert.equal(v[0].fn, 'wipe');
  assert.equal(v[0].target, 'public.wipe');
});

test('findUnpinnedDefiners carries the schema through', () => {
  const files = [
    { name: '100_a.sql', sql: `
        create function app.none() returns text language plpgsql security definer
          as $f$ begin return 'x'; end; $f$;` },
  ];
  const r = findUnpinnedDefiners(files, { baseline: 0 });
  assert.equal(r.unpinned[0].target, 'app.none');
  assert.equal(r.unpinned[0].schema, 'app');
});
