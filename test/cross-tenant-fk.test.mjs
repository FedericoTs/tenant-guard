/**
 * cross-tenant-fk pure-logic tests.
 *
 * `candidateFks` carries the weight: it decides what gets probed at all, and the
 * cases it must EXCLUDE (a key that already carries the tenant, a lookup table
 * with no tenant column, a self-reference) are what keep this guard from
 * flagging every foreign key in a normal schema.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  foreignKeysSql,
  tenantColumnsSql,
  tenantColumnMap,
  candidateFks,
  crossTenantRowsSql,
  parentTargetSql,
  otherChildTenantSql,
  repointProbeSql,
  describeAction,
  isDestructive,
  classifyFk,
} from '../src/guards/cross-tenant-fk.mjs';

// ── SQL ──────────────────────────────────────────────────────────────

test('foreignKeysSql: real FKs only, both sides in scope, with the referential actions', () => {
  const { text, values } = foreignKeysSql(['public']);
  assert.match(text, /contype = 'f'/);
  assert.match(text, /confdeltype/);
  assert.match(text, /with ordinality/); // column order must survive
  assert.deepEqual(values, [['public']]);
});

test('tenantColumnsSql: tables and partitioned parents, dropped columns excluded', () => {
  const { text, values } = tenantColumnsSql(['public'], ['organization_id']);
  assert.match(text, /relkind in \('r', 'p'\)/);
  assert.match(text, /attisdropped/);
  assert.deepEqual(values, [['public'], ['organization_id']]);
});

test('tenantColumnMap: first tenant column per table wins', () => {
  const m = tenantColumnMap([
    { schema: 'public', table: 'tasks', column: 'organization_id' },
    { schema: 'public', table: 'tasks', column: 'tenant_id' },
  ]);
  assert.equal(m.get('public.tasks'), 'organization_id');
});

// ── which FKs can even express a cross-tenant row ────────────────────

const TC = tenantColumnMap([
  { schema: 'public', table: 'tasks', column: 'organization_id' },
  { schema: 'public', table: 'projects', column: 'organization_id' },
  { schema: 'public', table: 'countries', column: null },
]);

const FK = {
  name: 'tasks_project_id_fkey',
  child_schema: 'public', child_table: 'tasks',
  parent_schema: 'public', parent_table: 'projects',
  on_delete: 'c', on_update: 'a',
  child_columns: ['project_id'], parent_columns: ['id'],
};

test('a single-column FK between two tenant tables is a candidate', () => {
  const [c] = candidateFks([FK], TC);
  assert.equal(c.id, 'public.tasks::tasks_project_id_fkey');
  assert.equal(c.childTenant, 'organization_id');
  assert.equal(c.childColumn, 'project_id');
  assert.equal(c.composite, false);
});

test('a key that ALREADY carries the tenant is excluded — the bad row is unrepresentable', () => {
  const composite = { ...FK, child_columns: ['organization_id', 'project_id'], parent_columns: ['organization_id', 'id'] };
  assert.deepEqual(candidateFks([composite], TC), []);
});

test('a reference to a shared lookup table (no tenant column) is excluded', () => {
  const lookup = { ...FK, parent_table: 'countries', parent_columns: ['code'] };
  assert.deepEqual(candidateFks([lookup], TC), []);
});

test('a self-reference is excluded — a hierarchy inside one tenant is not a boundary', () => {
  const self = { ...FK, parent_table: 'tasks', child_columns: ['parent_task_id'] };
  assert.deepEqual(candidateFks([self], TC), []);
});

test('a composite key that still omits the tenant IS a candidate, marked as composite', () => {
  const c = candidateFks([{ ...FK, child_columns: ['project_id', 'seq'], parent_columns: ['id', 'seq'] }], TC)[0];
  assert.equal(c.composite, true);
  assert.equal(c.childColumn, null); // not re-pointable by a single-column update
});

// ── generated SQL is identifier-safe ─────────────────────────────────

test('crossTenantRowsSql: joins child to parent and compares the tenants', () => {
  const fk = candidateFks([FK], TC)[0];
  const { text } = crossTenantRowsSql(fk);
  assert.match(text, /"public"\."tasks"/);
  assert.match(text, /"public"\."projects"/);
  assert.match(text, /is distinct from/); // NULL tenants must not silently match
});

test('generated SQL quotes every identifier', () => {
  const weird = candidateFks([{ ...FK, child_table: 'ta"sks' }], tenantColumnMap([
    { schema: 'public', table: 'ta"sks', column: 'organization_id' },
    { schema: 'public', table: 'projects', column: 'organization_id' },
  ]))[0];
  assert.match(crossTenantRowsSql(weird).text, /"ta""sks"/); // doubled, not escaped out
  assert.match(repointProbeSql(weird, 1, 'org_A').text, /"ta""sks"/);
});

test('parentTargetSql and repointProbeSql are parameterised, not interpolated', () => {
  const fk = candidateFks([FK], TC)[0];
  assert.match(parentTargetSql(fk).text, /limit 1/);
  const probe = repointProbeSql(fk, 42, 'org_A');
  assert.match(probe.text, /set "project_id" = \$1 where "organization_id" = \$2/);
  assert.deepEqual(probe.values, [42, 'org_A']);
});

test('every *Sql helper returns a COMPLETE spec, callable as q(text, values)', () => {
  // A helper whose SQL had placeholders but returned `values: []` worked only
  // because its one caller passed them separately — a trap for the next one.
  const fk = candidateFks([FK], TC)[0];
  for (const spec of [
    crossTenantRowsSql(fk),
    parentTargetSql(fk),
    otherChildTenantSql(fk, 'org_B'),
    repointProbeSql(fk, 1, 'org_A'),
  ]) {
    const placeholders = new Set(spec.text.match(/\$\d+/g) ?? []);
    assert.equal(
      spec.values.length, placeholders.size,
      `spec has ${placeholders.size} placeholder(s) but ${spec.values.length} value(s): ${spec.text.trim().slice(0, 60)}`,
    );
  }
});

// ── referential actions ──────────────────────────────────────────────

test('describeAction / isDestructive cover every code', () => {
  assert.equal(describeAction('c'), 'CASCADE');
  assert.equal(describeAction('n'), 'SET NULL');
  assert.equal(describeAction('r'), 'RESTRICT');
  assert.equal(describeAction('a'), 'NO ACTION');
  assert.equal(describeAction('?'), 'NO ACTION'); // unknown falls back safely
  assert.equal(isDestructive('c'), true);
  assert.equal(isDestructive('n'), true);
  assert.equal(isDestructive('r'), false);
});

// ── the verdict ──────────────────────────────────────────────────────

const CANDIDATE = candidateFks([FK], TC)[0];

test('LEAK: rows that already cross tenants — corruption in the data now', () => {
  const v = classifyFk({ fk: CANDIDATE, existingCrossTenant: 3 });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'existing-cross-tenant-reference');
  assert.match(v.message, /3 row\(s\)/);
  assert.match(v.message, /not a hypothetical/);
  assert.match(v.message, /DELETES these rows/); // ON DELETE CASCADE
});

test('LEAK: the probe landed — proven capability', () => {
  const v = classifyFk({ fk: CANDIDATE, probe: 'landed' });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'cross-tenant-reference');
  assert.match(v.message, /rolled-back transaction/);
  assert.match(v.message, /ALWAYS bypass/);
  assert.match(v.fix, /FOREIGN KEY \(organization_id, project_id\)/);
});

test('OK: a refused probe is a real pass, and says what was attempted', () => {
  const v = classifyFk({ fk: CANDIDATE, probe: 'blocked' });
  assert.equal(v.status, 'ok');
  assert.match(v.message, /attempted and refused/);
});

test('NOTE: unprovable is reported structurally, never as a pass', () => {
  const v = classifyFk({ fk: CANDIDATE, probe: 'unknown', probeReason: 'no parent rows to point at' });
  assert.equal(v.status, 'note');
  assert.match(v.message, /no parent rows to point at/);
  assert.match(v.message, /representable/);
});

test('RESTRICT inverts the consequence rather than removing it', () => {
  const restrict = { ...CANDIDATE, on_delete: 'r' };
  const v = classifyFk({ fk: restrict, probe: 'landed' });
  assert.match(v.message, /PINS the other tenant's row/);
  assert.doesNotMatch(v.message, /DELETES/);
});

test('SET NULL is destructive too, and worded as a silent rewrite', () => {
  const v = classifyFk({ fk: { ...CANDIDATE, on_delete: 'n' }, probe: 'landed' });
  assert.match(v.message, /silently rewrites/);
});

test('the fix names the allowlist entry for a deliberate cross-tenant reference', () => {
  const v = classifyFk({ fk: CANDIDATE, probe: 'landed' });
  assert.match(v.fix, /crossTenantFk\.allowlist/);
  assert.match(v.fix, /public\.tasks::tasks_project_id_fkey/);
});
