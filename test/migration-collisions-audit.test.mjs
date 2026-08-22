/**
 * migration-collisions — audit fixes, each one measured against PGlite on an
 * EMPTY database before it was written.
 *
 * The guard has exactly one build-failing condition, `dependency-inversion`, and
 * three separate shapes of correct migration were hitting it:
 *
 *   1. ICU collation. The tied group was analysed with `localeCompare(…, 'en')`
 *      while every runner sorts by code unit, so on a name differing by case or
 *      by punctuation the group was evaluated backwards.
 *   2. plpgsql bodies. Postgres does not name-resolve a non-SQL function body at
 *      CREATE time, so a helpers-then-tables split under one date prefix applies
 *      fine — the guard called it "a migration that cannot apply".
 *   3. Objects an EARLIER migration already created. `created`/`referenced` were
 *      computed over the tied group alone, so any re-declaration inside the
 *      group (`IF NOT EXISTS`, `OR REPLACE VIEW`) was scored as first creation.
 *
 * And two conclusive breaks were passing: `GRANT … ON TABLE t` (the object type
 * keyword was captured instead of the table name) and a dependency crossing an
 * unpadded-numbering boundary.
 *
 * Every fixture below was applied to a fresh PGlite instance in code-unit
 * filename order — the order `readdirSync().sort()`, Go `sort.Strings` and Java
 * `String.compareTo` produce — and the recorded result is in the comment.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  run,
  referencedObjects,
  deferredReferencedObjects,
  findDependencyInversions,
  compareByFilename,
  splitDeferredBodies,
} from '../src/guards/migration-collisions.mjs';

function withMigrations(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-mca-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const show = (res) => JSON.stringify(res, null, 2);

// ── 1. filename order is CODE UNIT, not ICU collation ─────────────────

test('the comparator matches the runner, not ICU: uppercase and `_` sort where the bytes say', () => {
  // Measured on this repo's node (full ICU, 'en'): localeCompare returns +1 for
  // both of these pairs, code-unit order returns -1.
  assert.ok(compareByFilename('0012_Vendors.sql', '0012_add_note.sql') < 0);
  assert.ok(compareByFilename('0001_x1.sql', '0001_x_1.sql') < 0);
  assert.equal(compareByFilename('20260531_a.sql', '20260531_a.sql'), 0);
  assert.ok(compareByFilename({ name: '0012_add_note.sql' }, { name: '0012_Vendors.sql' }) > 0);
});

test('an uppercase-first tied pair that APPLIES CLEANLY is not failed', () => {
  // PGlite, empty database, code-unit order: APPLIED OK / APPLIED OK.
  // Only ICU order fails, with `relation "public.api_keys" does not exist`.
  withMigrations({
    '20260531_API_keys_table.sql': 'CREATE TABLE public.api_keys (id uuid primary key, org_id uuid not null);',
    '20260531_add_rls.sql':
      'ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY; CREATE POLICY p ON public.api_keys USING (true);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, show(res));
    assert.equal(res.violations.length, 0);
  });
});

test('the mirror image — an inversion ICU order HID — now fails', () => {
  // `0002_x1.sql` sorts BEFORE `0002_x_1.sql` by code unit ('1' < '_').
  // PGlite: FAILED 0002_x1.sql -> relation "public.u" does not exist.
  withMigrations({
    '0002_x_1.sql': 'CREATE TABLE public.u (id int primary key);',
    '0002_x1.sql': 'ALTER TABLE public.u ADD COLUMN n text;',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, false, show(res));
    assert.equal(res.violations[0].kind, 'dependency-inversion');
    assert.equal(res.violations[0].where, '0002_x1.sql, 0002_x_1.sql');
  });
});

// ── 2. plpgsql bodies are not resolved at CREATE time ─────────────────

test('a plpgsql body reading a later sibling\'s table is a NOTE, not a build failure', () => {
  // PGlite, empty database, check_function_bodies = on: APPLIED OK / APPLIED OK,
  // and `select public.f()` then returns 0.
  withMigrations({
    '0002_a_fn.sql':
      'CREATE OR REPLACE FUNCTION public.f() RETURNS bigint LANGUAGE plpgsql AS $$ ' +
      'BEGIN RETURN (SELECT count(*) FROM public.later_tbl); END; $$;',
    '0002_b_tbl.sql': 'CREATE TABLE public.later_tbl (id int primary key);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, show(res));
    assert.equal(res.violations.length, 0);
    const note = res.notes.find((n) => n.where === '0002_a_fn.sql, 0002_b_tbl.sql');
    assert.ok(note, show(res));
    // The signal is kept, not dropped: the function IS broken until b runs.
    assert.match(note.message, /later_tbl/);
    assert.match(note.message, /relation does not exist/);
  });
});

test('the same body in LANGUAGE sql still FAILS — Postgres does resolve those', () => {
  // PGlite: FAILED 0002_a_fn.sql -> relation "public.later_tbl" does not exist.
  withMigrations({
    '0002_a_fn.sql':
      'CREATE OR REPLACE FUNCTION public.f() RETURNS bigint LANGUAGE sql AS $$ ' +
      'SELECT count(*) FROM public.later_tbl $$;',
    '0002_b_tbl.sql': 'CREATE TABLE public.later_tbl (id int primary key);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, false, show(res));
    assert.equal(res.violations[0].object ?? res.violations[0].message.includes('later_tbl'), true);
  });
});

test('a plpgsql function the same migration CALLS at top level still FAILS', () => {
  // The body really does run during this migration.
  // PGlite: FAILED 0002_a_fn.sql -> relation "public.later_tbl" does not exist.
  withMigrations({
    '0002_a_fn.sql':
      'CREATE FUNCTION public.f() RETURNS bigint LANGUAGE plpgsql AS $$ ' +
      'BEGIN RETURN (SELECT count(*) FROM public.later_tbl); END; $$;\nSELECT public.f();',
    '0002_b_tbl.sql': 'CREATE TABLE public.later_tbl (id int primary key);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, false, show(res));
    assert.equal(res.violations[0].kind, 'dependency-inversion');
  });
});

test('`EXECUTE FUNCTION f()` in a CREATE TRIGGER is a binding, not a call', () => {
  // PGlite: OK / OK / OK — the trigger body runs on later DML, not now.
  withMigrations({
    '0000_base.sql': 'CREATE TABLE public.base (id int primary key);',
    '0002_a_fn.sql':
      'CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$ ' +
      'BEGIN PERFORM 1 FROM public.later_tbl; RETURN NEW; END; $$;\n' +
      'CREATE TRIGGER t BEFORE INSERT ON public.base FOR EACH ROW EXECUTE FUNCTION public.touch();',
    '0002_b_tbl.sql': 'CREATE TABLE public.later_tbl (id int primary key);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, show(res));
  });
});

test('LANGUAGE stated AFTER the body is still read', () => {
  const sql = 'CREATE FUNCTION public.g() RETURNS bigint AS $$ BEGIN RETURN (SELECT count(*) FROM public.hidden); END; $$ LANGUAGE plpgsql;';
  assert.equal(referencedObjects(sql).has('hidden'), false);
  assert.equal(deferredReferencedObjects(sql).has('hidden'), true);
});

test('an unrecognisable body or an unstated language stays SCANNED — unknown is not safe', () => {
  // No LANGUAGE clause at all: keep counting the body. "Unknown" must never
  // silently become "applies fine".
  const noLang = 'CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 FROM public.mystery $$;';
  assert.equal(referencedObjects(noLang).has('mystery'), true);
  assert.equal(deferredReferencedObjects(noLang).size, 0);
  // Everything outside the body keeps counting too.
  const withTrigger =
    'CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM 1 FROM public.hidden; RETURN NEW; END; $$;\n' +
    'CREATE TRIGGER tr AFTER INSERT ON public.trig_tbl FOR EACH ROW EXECUTE FUNCTION f();';
  assert.equal(referencedObjects(withTrigger).has('trig_tbl'), true);
  assert.equal(referencedObjects(withTrigger).has('hidden'), false);
  // The blanked body leaves the signature in place.
  assert.match(splitDeferredBodies(withTrigger).code, /RETURNS trigger LANGUAGE plpgsql/);
});

// ── 3. objects an EARLIER migration already created ───────────────────

test('re-declaring an object an earlier migration created is not an inversion', () => {
  // PGlite, empty database, filename order: OK / OK / OK, final columns
  // flag,id,org_id.
  withMigrations({
    '0000_base.sql': 'create table public.existing (id int primary key, org_id uuid not null);',
    '0003_a_alter.sql': 'alter table public.existing add column if not exists flag boolean;',
    '0003_b_idem.sql': 'create table if not exists public.existing (id int primary key, org_id uuid not null);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, show(res));
    assert.equal(res.violations.length, 0);
  });
});

test('CREATE OR REPLACE VIEW re-declared later in the group is not an inversion either', () => {
  // Not one narrow keyword: PGlite applies all three OK.
  withMigrations({
    '0000_base.sql':
      'create table public.docs (id int primary key, org_id uuid); create view public.docs_v as select id from public.docs;',
    '0007_a_read.sql': 'create table public.report as select id from public.docs_v;',
    '0007_b_replace.sql': 'create or replace view public.docs_v as select id, org_id from public.docs;',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, show(res));
  });
});

test('the SAME shape without a prior creator still FAILS — the modifier proves nothing', () => {
  // PGlite: FAILED 0009_a_read.sql -> relation "public.brandnew" does not exist,
  // even though the creating file carries IF NOT EXISTS. Filtering on the
  // modifier would have silenced this.
  withMigrations({
    '0009_a_read.sql': 'alter table public.brandnew add column flag boolean;',
    '0009_b_create.sql': 'create table if not exists public.brandnew (id int primary key);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, false, show(res));
    assert.match(res.violations[0].message, /No earlier migration creates it either/);
  });
});

test('findDependencyInversions takes the prior-history set explicitly', () => {
  const group = [
    { name: 'a_uses.sql', sql: 'select * from notes;' },
    { name: 'b_creates.sql', sql: 'create table if not exists notes (id int);' },
  ];
  assert.equal(findDependencyInversions(group).length, 1);
  assert.deepEqual(findDependencyInversions(group, { priorCreated: new Set(['notes']) }), []);
});

// ── 4. GRANT … ON TABLE t ─────────────────────────────────────────────

test('the object-type keyword no longer eats the object name', () => {
  assert.deepEqual([...referencedObjects('GRANT SELECT ON TABLE public.grantme TO PUBLIC;')], ['grantme']);
  assert.deepEqual([...referencedObjects('GRANT USAGE ON SEQUENCE public.myseq TO anon;')], ['myseq']);
  assert.equal(referencedObjects('REVOKE EXECUTE ON FUNCTION public.wipe(uuid) FROM PUBLIC;').has('wipe'), true);
  assert.equal(referencedObjects('GRANT USAGE ON SCHEMA app TO anon;').has('app'), true);
  assert.equal(
    referencedObjects('GRANT SELECT ON ALL TABLES IN SCHEMA app TO anon;').has('app'), true,
  );
});

test('the keyword filter still swallows ON CONFLICT / VALUES / DO UPDATE SET', () => {
  const refs = referencedObjects('insert into t (a) values (1) on conflict (a) do update set a = 1;');
  assert.deepEqual([...refs], ['t']);
});

test('`GRANT … ON TABLE t` before the migration that creates t now FAILS', () => {
  // PGlite, empty database: FAILED 0004_a_grant.sql -> relation
  // "public.grantme" does not exist. The bare-`ON` twin was already failed; this
  // is the identical breakage written the other way.
  withMigrations({
    '0004_a_grant.sql': 'GRANT SELECT ON TABLE public.grantme TO PUBLIC;',
    '0004_b_create.sql': 'CREATE TABLE public.grantme (id int primary key);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, false, show(res));
    assert.equal(res.violations[0].kind, 'dependency-inversion');
    assert.match(res.violations[0].message, /"grantme"/);
  });
});

// ── 5. dependencies crossing an unpadded-numbering boundary ───────────

test('an unpadded-numbering break is named, with both files and the object', () => {
  // PGlite, filename order: FAILED 10_use_widgets.sql -> relation
  // "public.widgets" does not exist. Before, the only output was "pad the
  // numbers" — nothing said anything actually breaks.
  //
  // Deliberately still a NOTE: Flyway and golang-migrate sort NUMERICALLY, and
  // under that runner these two files are correct. Failing a build on correct
  // code is the more expensive error.
  withMigrations({
    '9_create_widgets.sql': 'CREATE TABLE public.widgets (id int primary key);',
    '10_use_widgets.sql': 'ALTER TABLE public.widgets ADD COLUMN name text;',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, show(res));
    const crossing = res.notes.find((n) => n.where === '10_use_widgets.sql, 9_create_widgets.sql');
    assert.ok(crossing, show(res));
    assert.match(crossing.message, /"widgets"/);
    assert.match(crossing.message, /fail to apply this against an empty database/);
    assert.match(crossing.message, /NUMERICALLY \(Flyway, golang-migrate\) will not/);
    assert.match(res.notes.find((n) => n.where === '(numbering)').message, /1 dependency\/dependencies actually cross/);
  });
});

test('unpadded numbering with nothing crossing raises no pair note', () => {
  // PGlite, filename order (0_base, 10_more, 11_last, 1_init, 2_use): all OK —
  // `notes` is created by a file that sorts before every reader. The pair scan
  // must stay silent here, or the escalation would be cry-wolf.
  withMigrations({
    '0_base.sql': 'create table public.notes (id int primary key);',
    '1_init.sql': 'alter table public.notes add column a int;',
    '2_use.sql': 'select * from public.notes;',
    '10_more.sql': 'alter table public.notes add column t text;',
    '11_last.sql': 'select * from public.notes;',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, show(res));
    assert.deepEqual(res.notes.map((n) => n.where), ['(numbering)']);
    assert.doesNotMatch(res.notes[0].message, /actually cross/);
  });
});

test('the numbering finding has an escape hatch, for a repo whose runner sorts numerically', () => {
  withMigrations({
    '9_create_widgets.sql': 'CREATE TABLE public.widgets (id int primary key);',
    '10_use_widgets.sql': 'ALTER TABLE public.widgets ADD COLUMN name text;',
  }, (dir) => {
    const res = run({ dir, grandfather: ['(numbering)'] });
    assert.equal(res.ok, true, show(res));
    assert.deepEqual(res.notes, []);
  });
});
