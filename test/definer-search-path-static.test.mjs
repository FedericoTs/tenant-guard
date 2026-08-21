/**
 * The static half of the search_path check — no database required.
 *
 * `definer-rpc` settles this conclusively against a real database, and
 * `create-grants` reports the CREATE grants that are the precondition. What this
 * adds is that it needs neither: it lands on the pull request that introduces
 * the function, in a repository that has never wired up a test database. So it
 * reports NOTES, never failures — whether an unpinned path is exploitable is not
 * a question migrations can answer, and failing a build on a maybe is how a
 * guard gets switched off.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  functionSearchPath,
  searchPathReachesPublicFirst,
  findUnpinnedDefiners,
  extractFunctionDefs,
  run,
} from '../src/guards/definer-grants.mjs';

function withMigrations(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-sp-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const definer = (name, clause) => `
  create function ${name}() returns text
    language plpgsql security definer ${clause}
  as $fn$ begin return (select v from lookup limit 1); end; $fn$;
`;

// ── the parser ───────────────────────────────────────────────────────

test('functionSearchPath reads the clause off the header', () => {
  assert.deepEqual(functionSearchPath(definer('f', 'set search_path = pg_catalog, app')), ['pg_catalog', 'app']);
  assert.deepEqual(functionSearchPath(definer('f', 'SET search_path TO public')), ['public']);
  assert.equal(functionSearchPath(definer('f', '')), null);
});

test('functionSearchPath ignores a SET inside the BODY — a different thing entirely', () => {
  // `set search_path = evil` in a plpgsql body runs at call time and does not
  // attach to the function. Reading it as a pin would be a false negative.
  const sql = `
    create function f() returns text language plpgsql security definer
    as $fn$ begin set search_path = evil; return 'x'; end; $fn$;`;
  assert.equal(functionSearchPath(sql), null);
});

test('functionSearchPath handles a quoted schema name', () => {
  assert.deepEqual(functionSearchPath(definer('f', 'set search_path = "my schema", public')), ['my schema', 'public']);
});

test('searchPathReachesPublicFirst is about ORDER, not membership', () => {
  assert.equal(searchPathReachesPublicFirst(['public', 'app']), true);
  assert.equal(searchPathReachesPublicFirst(['app', 'public']), false);
  assert.equal(searchPathReachesPublicFirst(['pg_catalog', 'public']), false);
  assert.equal(searchPathReachesPublicFirst([]), false);
});

test('extractFunctionDefs carries the verdict, not just the clause', () => {
  const [good] = extractFunctionDefs(definer('a', 'set search_path = pg_catalog, public, pg_temp'));
  const [bad] = extractFunctionDefs(definer('b', 'set search_path = public'));
  const [none] = extractFunctionDefs(definer('c', ''));
  assert.equal(good.searchPathPinned, true);
  assert.equal(bad.searchPathPinned, false, 'pinned to public first is not pinned in any way that helps');
  assert.equal(none.searchPathPinned, false);
});

// ── the finder ───────────────────────────────────────────────────────

test('findUnpinnedDefiners splits the three states and counts the good ones', () => {
  const files = [{
    name: '001.sql',
    sql: definer('safe', 'set search_path = pg_catalog, public, pg_temp')
       + definer('weak', 'set search_path = public')
       + definer('none', ''),
  }];
  const r = findUnpinnedDefiners(files);
  assert.deepEqual(r.pinned.map((f) => f.name), ['safe']);
  assert.deepEqual(r.publicFirst.map((f) => f.name), ['weak']);
  assert.deepEqual(r.unpinned.map((f) => f.name), ['none']);
  assert.deepEqual(r.noTemp.map((f) => f.name), []);
});

test('a TRIGGER function is skipped — it has no caller path to hijack', () => {
  const files = [{
    name: '001.sql',
    sql: `create function t() returns trigger language plpgsql security definer
          as $fn$ begin return new; end; $fn$;`,
  }];
  const r = findUnpinnedDefiners(files);
  assert.deepEqual([...r.unpinned, ...r.publicFirst], []);
});

test('the allowlist and the baseline both apply', () => {
  const files = [{ name: '001.sql', sql: definer('none', '') }];
  assert.deepEqual(findUnpinnedDefiners(files, { allowlist: ['none'] }).unpinned, []);
  assert.deepEqual(findUnpinnedDefiners(files, { baseline: 1 }).unpinned, []);
});

// ── end to end ───────────────────────────────────────────────────────

test('run() reports search_path as NOTES and never fails the build on it', () => {
  withMigrations({ '001_fns.sql': definer('none', '') + definer('weak', 'set search_path = public') }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, 'not conclusive from migrations alone — must not fail a build');
    assert.equal(res.violations.length, 0);
    assert.ok(res.notes.some((n) => /"none"/.test(n.message) && /no SET search_path/.test(n.message)));
    assert.ok(res.notes.some((n) => /"weak"/.test(n.message) && /protects nothing/.test(n.message)));
  });
});

test('the unpinned note hands off to the guards that can settle it', () => {
  withMigrations({ '001_fns.sql': definer('none', '') }, (dir) => {
    const note = run({ dir }).notes.find((n) => /"none"/.test(n.message));
    assert.match(note.message, /tenant-guard rpc/);
    assert.match(note.message, /tenant-guard creates/);
    assert.match(note.fix, /SET search_path = pg_catalog, public/);
  });
});

test('functions that pin correctly are COUNTED, not passed over in silence', () => {
  withMigrations({
    '001_fns.sql': definer('a', 'set search_path = pg_catalog, public, pg_temp')
                 + definer('b', 'set search_path = pg_catalog, public, pg_temp')
                 + definer('none', ''),
  }, (dir) => {
    const note = run({ dir }).notes.find((n) => n.where === '(search_path)');
    assert.ok(note, 'a report that only lists failures reads as if nothing is working');
    assert.match(note.message, /2 other SECURITY DEFINER function\(s\) pin/);
  });
});

test('an all-pinned migration set says nothing at all about search_path', () => {
  withMigrations({ '001_fns.sql': definer('a', 'set search_path = pg_catalog, public, pg_temp') }, (dir) => {
    const res = run({ dir });
    assert.equal(res.notes.some((n) => /search_path/.test(n.message ?? '')), false);
  });
});
