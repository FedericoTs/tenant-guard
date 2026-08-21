/**
 * Migration ORDER — recalibration, and a real ordering bug it uncovered.
 *
 * Reported: `migration-collisions` failed a real repository on eleven historical
 * same-DATE prefix groups. Supabase applies migrations in lexicographic
 * full-filename order, so `20260531_a.sql` deterministically precedes
 * `20260531_b.sql`; a shared prefix alone is a naming choice.
 *
 * Checking that turned up something worse: every guard reasoning about "the net
 * state of history" sorted on the numeric prefix ALONE. For tied prefixes the
 * comparator returned 0, so a stable sort kept `readdirSync` order — filesystem
 * order — and the net state could be computed in the opposite order from the one
 * Postgres will see. On the exact input shape the guard was flagging.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { compareMigrations, lexicographicDisagreesWithNumeric } from '../src/guards/definer-grants.mjs';
import {
  createdObjects,
  referencedObjects,
  findDependencyInversions,
  run,
} from '../src/guards/migration-collisions.mjs';

function withMigrations(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-mig-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── the comparator ───────────────────────────────────────────────────

test('tied prefixes sort by FULL filename, the way migrations are applied', () => {
  const files = [{ name: '20260531_b_drop.sql' }, { name: '20260531_a_create.sql' }];
  assert.deepEqual(
    [...files].sort(compareMigrations).map((f) => f.name),
    ['20260531_a_create.sql', '20260531_b_drop.sql'],
  );
});

test('the comparator is total — no tie is left to filesystem order', () => {
  // The bug: (num(a) ?? 0) - (num(b) ?? 0) returns 0 for a shared prefix, so a
  // stable sort preserved readdirSync order, which is not alphabetical.
  const a = { name: '20260531_a.sql' };
  const b = { name: '20260531_b.sql' };
  assert.ok(compareMigrations(a, b) < 0);
  assert.ok(compareMigrations(b, a) > 0);
  assert.equal(compareMigrations(a, a), 0);
});

test('lexicographicDisagreesWithNumeric spots unpadded numbering', () => {
  assert.equal(lexicographicDisagreesWithNumeric(['9_x.sql', '10_y.sql']), true);
  assert.equal(lexicographicDisagreesWithNumeric(['009_x.sql', '010_y.sql']), false);
  assert.equal(lexicographicDisagreesWithNumeric(['20260531_a.sql', '20260531_b.sql']), false);
});

// ── dependency inversion ─────────────────────────────────────────────

test('createdObjects / referencedObjects read the statements, not the prose', () => {
  assert.ok(createdObjects('CREATE TABLE public.trips (id int);').has('trips'));
  assert.ok(createdObjects('create or replace view v as select 1;').has('v'));
  assert.ok(referencedObjects('SELECT * FROM public.notes;').has('notes'));
  assert.ok(referencedObjects('ALTER TABLE trips ADD COLUMN x int;').has('trips'));
  assert.equal(createdObjects('-- create table ghost (id int);').has('ghost'), false);
});

test('an inversion is only an inversion when the EARLIER file needs the LATER one', () => {
  const group = [
    { name: 'a_uses.sql', sql: 'select * from notes;' },
    { name: 'b_creates.sql', sql: 'create table notes (id int);' },
  ];
  const inv = findDependencyInversions(group);
  assert.equal(inv.length, 1);
  assert.equal(inv[0].object, 'notes');

  // The same two files the right way round are fine.
  assert.deepEqual(findDependencyInversions([group[1], group[0]]), []);
});

test('a file that creates AND uses its own table is not an inversion', () => {
  const group = [
    { name: 'a.sql', sql: 'create table t (id int); insert into t values (1);' },
    { name: 'b.sql', sql: 'create table t2 (id int);' },
  ];
  assert.deepEqual(findDependencyInversions(group), []);
});

// ── the recalibration, end to end ────────────────────────────────────

test('a same-DATE tie is a NOTE now, not a build failure — that was the reported noise', () => {
  withMigrations({
    '20260531_a_create.sql': 'create table trips (id int);',
    '20260531_b_alter.sql': 'alter table trips add column x int;',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.match(res.notes[0].message, /deterministic/);
  });
});

test('a real dependency inversion inside a tie still FAILS', () => {
  withMigrations({
    '20260601_a_uses.sql': 'select * from notes;',
    '20260601_b_creates.sql': 'create table notes (id int);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations[0].kind, 'dependency-inversion');
    assert.match(res.violations[0].message, /cannot apply against a fresh database/);
    assert.match(res.violations[0].fix, /EMPTY database/); // why it passes locally
  });
});

test('unique prefixes produce nothing at all', () => {
  withMigrations({
    '001_a.sql': 'create table a (id int);',
    '002_b.sql': 'create table b (id int);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true);
    assert.equal(res.notes.length, 0);
  });
});

test('unpadded numbering is called out, because the filenames win', () => {
  withMigrations({
    '9_early.sql': 'create table a (id int);',
    '10_later.sql': 'create table b (id int);',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true);
    assert.match(res.notes.find((n) => n.where === '(numbering)').message, /pad the numbers/);
  });
});

test('grandfathering still silences a group', () => {
  withMigrations({
    '20260601_a_uses.sql': 'select * from notes;',
    '20260601_b_creates.sql': 'create table notes (id int);',
  }, (dir) => {
    assert.equal(run({ dir, grandfather: ['20260601'] }).ok, true);
  });
});
