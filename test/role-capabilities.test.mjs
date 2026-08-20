/**
 * role-capabilities pure logic. The load-bearing decision here is the severity
 * split — what fails the build versus what is only surfaced — so that is what
 * gets pinned down.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  functionGrantsSql,
  authGrantsSql,
  classifyFunction,
  classifyAuthTable,
  DEFAULTS,
} from '../src/guards/role-capabilities.mjs';

test('functionGrantsSql / authGrantsSql: parameterised privilege reads, nothing executed', () => {
  const f = functionGrantsSql(['dblink'], 'authenticated');
  assert.match(f.text, /has_function_privilege\(\$2::text/);
  assert.deepEqual(f.values, [['dblink'], 'authenticated']);

  const a = authGrantsSql(['users'], 'authenticated');
  assert.match(a.text, /nspname = 'auth'/);
  assert.match(a.text, /has_table_privilege\(\$2::text/);
  assert.deepEqual(a.values, [['users'], 'authenticated']);
});

test('the two families are disjoint, and dblink/file-reads are in the failing one', () => {
  for (const f of ['dblink', 'dblink_exec', 'pg_read_file', 'lo_import']) {
    assert.ok(DEFAULTS.rlsBypassFunctions.includes(f), `${f} should fail the build`);
    assert.ok(!DEFAULTS.egressFunctions.includes(f));
  }
  for (const f of ['http_post', 'http_get']) {
    assert.ok(DEFAULTS.egressFunctions.includes(f), `${f} should only be surfaced`);
    assert.ok(!DEFAULTS.rlsBypassFunctions.includes(f));
  }
});

test('classify: dblink -> leak, and the message explains WHY it defeats RLS', () => {
  const v = classifyFunction({ schema: 'public', name: 'dblink', args: 'text, text', family: 'rls-bypass' });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /NEW database connection/);
  assert.match(v.message, /nothing to do with the caller's/);
});

test('classify: a file read -> leak with the other reason (never reaches the policy layer)', () => {
  const v = classifyFunction({ schema: 'public', name: 'pg_read_file', args: 'text', family: 'rls-bypass' });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /outside the policy layer/);
});

test('classify: egress -> NOTE, and says explicitly why it is not a build failure', () => {
  const v = classifyFunction({ schema: 'net', name: 'http_post', args: 'text, jsonb', family: 'egress' });
  assert.equal(v.status, 'note');
  assert.match(v.message, /not a cross-tenant READ/);
  assert.match(v.message, /SSRF/);
});

test('classify: the REVOKE fix always names PUBLIC — revoking from the role alone is a no-op', () => {
  const v = classifyFunction({ schema: 'public', name: 'dblink', args: 'text', family: 'rls-bypass', role: 'authenticated' });
  assert.match(v.fix, /FROM authenticated, PUBLIC/);
});

test('classifyAuthTable: always a leak, and the fix is a synced profiles table', () => {
  const v = classifyAuthTable({ table: 'users', role: 'authenticated' });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /identity store/);
  assert.match(v.message, /no tenant column/);
  assert.match(v.fix, /REVOKE SELECT ON auth\.users/);
  assert.match(v.fix, /trigger on auth\.users/);
});
