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

test('readSurfaceSql: binds role + schema/table, asks for grant AND privileged total', () => {
  const s = readSurfaceSql('public', 'invoices', 'anon');
  assert.match(s.text, /has_table_privilege\(\$1,.*'SELECT'\)/);
  assert.match(s.text, /count\(\*\)::int/);
  assert.match(s.text, /from "public"\."invoices"/);
  assert.deepEqual(s.values, ['anon', 'public', 'invoices']);
});

test('anonSelectCountSql: whole-table count, no WHERE', () => {
  const c = anonSelectCountSql('public', 'invoices');
  assert.match(c.text, /^select count\(\*\)::int as n from "public"\."invoices"$/);
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

test('violationForRead: names the table, the role, and the REVOKE / allowlist fix', () => {
  const v = violationForRead('public.invoices', 'public', 'invoices', 'anon', true);
  assert.equal(v.where, 'public.invoices');
  assert.match(v.message, /"anon" role can SELECT/);
  assert.match(v.fix, /REVOKE SELECT ON "public"\."invoices" FROM anon/);
  assert.match(v.fix, /allowlist/);
});
