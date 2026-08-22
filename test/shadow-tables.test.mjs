/**
 * shadow-tables pure logic. The body scan carries the false-positive risk (plpgsql
 * gives no catalog dependencies, so it is text analysis), and the verdict rules
 * decide what is a build failure versus somebody else's problem.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  triggersSql,
  destinationSql,
  writeTargets,
  classifyDestination,
} from '../src/guards/shadow-tables.mjs';

test('triggersSql: real triggers only, with the body of the function they call', () => {
  const { text, values } = triggersSql(['public']);
  assert.match(text, /pg_trigger/);
  assert.match(text, /not t\.tgisinternal/); // FK enforcement triggers aren't user triggers
  assert.match(text, /prosrc/);
  assert.deepEqual(values, [['public']]);
});

test('destinationSql: RLS, tenant column and the role\'s SELECT grant for each destination', () => {
  const { text, values } = destinationSql(['public.audit_log'], ['organization_id'], 'authenticated');
  assert.match(text, /relrowsecurity/);
  assert.match(text, /has_table_privilege\(\$3::text/);
  assert.deepEqual(values, [['public.audit_log'], ['organization_id'], 'authenticated']);
});

test('writeTargets: finds INSERT INTO and UPDATE … SET targets, schema-qualified or not', () => {
  assert.deepEqual(writeTargets(`begin insert into audit_log (a) values (1); end`), ['public.audit_log']);
  assert.deepEqual(writeTargets(`insert into ops.outbox (a) values (1)`), ['ops.outbox']);
  assert.deepEqual(writeTargets(`update cache set n = 1 where id = 2`), ['public.cache']);
  assert.deepEqual(writeTargets(`insert into "Audit_Log" (a) values (1)`), ['public.audit_log']); // quoted + case
});

test('writeTargets: NEW and OLD are trigger records, not tables', () => {
  assert.deepEqual(writeTargets(`begin update new set x = 1; return new; end`), []);
});

test('writeTargets: deduplicates, and uses the trigger table\'s schema as the default', () => {
  assert.deepEqual(
    writeTargets(`insert into audit_log (a) values (1); insert into audit_log (a) values (2);`, 'ops'),
    ['ops.audit_log'],
  );
});

test('writeTargets: silent on an empty or unreadable body (a limitation, not a guess)', () => {
  assert.deepEqual(writeTargets(null), []);
  assert.deepEqual(writeTargets(`begin execute 'insert into ' || t || ' values (1)'; end`), []);
});

test('classify: readable + no RLS -> leak, and the message names the missing tenant column', () => {
  const v = classifyDestination({ schema: 'public', table: 'audit_log', rlsEnabled: false, canSelect: true, tenantColumn: null, sources: ['public.invoices'] });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /no tenant column to scope it by/);
  assert.match(v.fix, /ADD COLUMN organization_id/);
});

test('classify: readable + no RLS but HAS a tenant column -> leak with the simpler fix', () => {
  const v = classifyDestination({ schema: 'public', table: 'outbox', rlsEnabled: false, canSelect: true, tenantColumn: 'organization_id', sources: ['public.invoices'] });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /despite carrying a "organization_id" column/);
  assert.doesNotMatch(v.fix, /ADD COLUMN/); // it already has one
});

// The old name for this case was "RLS on -> safe here (the other guards judge it
// on its merits)". That reason was wrong: with no tenant column, rls-proof never
// plans the table, so nothing downstream judges it. The verdict is still 'safe',
// but for the reason asserted here — RLS on with no policy denies every row.
// The decorative-policy case is in shadow-tables-audit.test.mjs.
test('classify: RLS on with no policy -> safe, Postgres denies every row', () => {
  assert.equal(classifyDestination({ schema: 'public', table: 'audit_log', rlsEnabled: true, canSelect: true }).status, 'safe');
});

test('classify: unreadable by the app role -> safe, nothing is exposed', () => {
  assert.equal(classifyDestination({ schema: 'public', table: 'audit_log', rlsEnabled: false, canSelect: false }).status, 'safe');
});
