/**
 * anon-reads pure-logic tests. The SQL builders and the verdict are I/O-free;
 * the end-to-end probe (against real Postgres) lives in the integration test.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  roleExistsSql,
  readSurfaceSql,
  anonSelectCountSql,
  classifyRead,
  violationForRead,
} from '../src/guards/anon-reads.mjs';

test('roleExistsSql: parameterises the role name', () => {
  const s = roleExistsSql('anon');
  assert.match(s.text, /pg_roles/);
  assert.deepEqual(s.values, ['anon']);
});

// CHANGED in 0.43. These two assertions pinned the shape the emptiness/cap fix
// removes: `readSurfaceSql` used to require `count(*)::int` over the relation (a
// full seq scan answering a yes/no question, taken even for relations anon cannot
// select at all), and `anonSelectCountSql` used to require an unbounded count
// (scanning past the point at which the verdict, `anonVisible > 0`, stops caring).
// Both are now asserted for the cheap shape instead; anon-reads-audit.test.mjs
// holds the tests that fail if the expensive shape ever comes back.
test('readSurfaceSql: binds role + schema/table, and is catalog-only', () => {
  const s = readSurfaceSql('public', 'invoices', 'anon');
  assert.match(s.text, /has_table_privilege\(\$1,.*'SELECT'\)/);
  assert.deepEqual(s.values, ['anon', 'public', 'invoices']);
});

test('anonSelectCountSql: whole-relation count (no WHERE), bounded by a LIMIT', () => {
  const c = anonSelectCountSql('public', 'invoices');
  assert.match(c.text, /^select count\(\*\)::int as n from \(select 1 from "public"\."invoices" limit \d+\) s$/);
  assert.doesNotMatch(c.text, /where/i);
});

test('classify: RLS OFF + anon SELECT grant -> leak (structural, the CVE class)', () => {
  const v = classifyRead({ rlsEnabled: false, canSelect: true, total: 0, anonVisible: 0 });
  assert.equal(v.status, 'leak');
  assert.equal(v.viaRls, false);
  assert.match(v.message, /RLS is OFF|CVE-2025-48757/);
});

test('classify: RLS OFF + no grant -> safe (anon can\'t select at all)', () => {
  assert.equal(classifyRead({ rlsEnabled: false, canSelect: false, total: 5, anonVisible: 0 }).status, 'safe');
});

test('classify: RLS ON + anon actually reads rows -> leak (probed, a policy permits it)', () => {
  const v = classifyRead({ rlsEnabled: true, canSelect: true, total: 9, anonVisible: 9 });
  assert.equal(v.status, 'leak');
  assert.equal(v.viaRls, true);
  assert.match(v.message, /proven by probe/);
});

test('classify: RLS ON + anon reads 0 of N rows -> safe (policy restricts)', () => {
  assert.equal(classifyRead({ rlsEnabled: true, canSelect: true, total: 9, anonVisible: 0 }).status, 'safe');
});

test('classify: RLS ON + empty table -> not-proven (never a silent pass)', () => {
  const v = classifyRead({ rlsEnabled: true, canSelect: true, total: 0, anonVisible: 0 });
  assert.equal(v.status, 'not-proven');
  assert.match(v.message, /empty/);
});

test('classify: a VIEW is NEVER judged structurally — rlsEnabled=false must not mean "leak"', () => {
  // Views always report relrowsecurity=false. Applying the table rule here would
  // false-flag every safe security_invoker view; the probe is the only authority.
  const v = classifyRead({ kind: 'view', rlsEnabled: false, canSelect: true, total: 9, anonVisible: 0 });
  assert.equal(v.status, 'safe');
});

test('classify: a MATERIALIZED VIEW anon can read -> leak naming that RLS never applies', () => {
  const v = classifyRead({ kind: 'matview', rlsEnabled: false, canSelect: true, total: 9, anonVisible: 9 });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /MATERIALIZED VIEW/);
  assert.match(v.message, /NEVER applies/i);
});

test('classify: no SELECT grant -> safe for any kind (nothing exposed)', () => {
  for (const kind of ['table', 'view', 'matview']) {
    assert.equal(classifyRead({ kind, rlsEnabled: false, canSelect: false, total: 5, anonVisible: 0 }).status, 'safe');
  }
});

test('violationForRead: a matview fix never suggests security_invoker', () => {
  const v = violationForRead('public.mv', 'public', 'mv', 'anon', true, { kind: 'matview' });
  assert.equal(v.kind, 'matview');
  assert.match(v.fix, /CANNOT be scoped by RLS/i);
  assert.doesNotMatch(v.fix, /ALTER VIEW/);
});

test('violationForRead: names the table, the role, and the REVOKE / allowlist fix', () => {
  const v = violationForRead('public.invoices', 'public', 'invoices', 'anon', true);
  assert.equal(v.where, 'public.invoices');
  assert.match(v.message, /"anon" role can SELECT/);
  assert.match(v.fix, /REVOKE SELECT ON "public"\."invoices" FROM anon/);
  assert.match(v.fix, /allowlist/);
});
