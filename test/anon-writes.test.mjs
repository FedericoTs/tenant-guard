/**
 * anon-writes pure-logic tests. The surface planning, grant reading, and SQL
 * builders are I/O-free; the real RLS-vs-grant verdict is proven end-to-end in
 * the integration test (that's where reliability actually lives).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  roleExistsSql,
  surfaceSql,
  planSurface,
  grantedWrites,
  anonUpdateSql,
  anonDeleteSql,
  violationFor,
} from '../src/guards/anon-writes.mjs';

test('roleExistsSql / surfaceSql: parameterised catalog reads', () => {
  assert.deepEqual(roleExistsSql('anon').values, ['anon']);
  const s = surfaceSql(['public'], 'anon');
  assert.match(s.text, /has_table_privilege/);
  assert.match(s.text, /relrowsecurity/);
  assert.match(s.text, /attgenerated = ''/); // picks a plain column for the UPDATE probe
  assert.deepEqual(s.values, [['public'], 'anon']);
});

test('planSurface: coerces flags, drops allowlisted tables (by id and by name)', () => {
  const rows = [
    { schema: 'public', table: 'cache', rls_enabled: 'f', can_insert: 't', can_update: 't', can_delete: 'f', probe_col: 'val' },
    { schema: 'public', table: 'contact', rls_enabled: false, can_insert: true, can_update: false, can_delete: false, probe_col: 'email' },
    { schema: 'public', table: 'audit', rls_enabled: true, can_insert: false, can_update: false, can_delete: false, probe_col: 'id' },
  ];
  const plan = planSurface(rows, ['public.contact', 'audit']);
  assert.deepEqual(plan.map((t) => t.table), ['cache']); // contact by id, audit by name
  assert.equal(plan[0].rlsEnabled, false);
  assert.equal(plan[0].canInsert, true);
  assert.equal(plan[0].probeCol, 'val');
});

test('grantedWrites: lists the write commands the role holds', () => {
  assert.deepEqual(grantedWrites({ canInsert: true, canUpdate: false, canDelete: true }), ['INSERT', 'DELETE']);
  assert.deepEqual(grantedWrites({ canInsert: false, canUpdate: false, canDelete: false }), []);
});

test('probe SQL: whole-table, no WHERE, idents quoted', () => {
  assert.equal(anonUpdateSql('public', 'cache', 'val'), 'update "public"."cache" set "val" = "val"');
  assert.equal(anonDeleteSql('public', 'cache'), 'delete from "public"."cache"');
});

test('violationFor: RLS-off vs RLS-on wording, carries commands + fix', () => {
  const t = { id: 'public.cache', schema: 'public', table: 'cache' };
  const off = violationFor(t, ['INSERT', 'UPDATE'], false);
  assert.match(off.message, /RLS is OFF/);
  assert.match(off.fix, /REVOKE INSERT, UPDATE/);
  assert.deepEqual(off.commands, ['INSERT', 'UPDATE']);

  const on = violationFor(t, ['UPDATE'], true);
  assert.match(on.message, /a policy permits it/);
});
