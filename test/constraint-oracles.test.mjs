/**
 * constraint-oracles pure-logic tests. The verdict rules carry all the
 * false-positive risk here, so they get the coverage.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  uniqueIndexSql,
  foreignKeySql,
  tenantColumnSql,
  classifyUniqueIndex,
  classifyForeignKey,
} from '../src/guards/constraint-oracles.mjs';

test('uniqueIndexSql: only unique indexes on real/partitioned tables, detects expression indexes', () => {
  const { text, values } = uniqueIndexSql(['public']);
  assert.match(text, /indisunique/);
  assert.match(text, /indisprimary/);
  assert.match(text, /has_expression/);
  assert.match(text, /relkind in \('r', 'p'\)/);
  assert.deepEqual(values, [['public']]);
});

test('foreignKeySql / tenantColumnSql: parameterised catalog reads', () => {
  assert.match(foreignKeySql(['public']).text, /contype = 'f'/);
  const t = tenantColumnSql(['public'], ['organization_id']);
  assert.match(t.text, /array_position/); // tenant column chosen by priority
  assert.deepEqual(t.values, [['public'], ['organization_id']]);
});

test('classifyUniqueIndex: unique key omitting the tenant column -> oracle', () => {
  const v = classifyUniqueIndex({ columns: ['email'], types: ['text'], tenantColumn: 'organization_id' });
  assert.equal(v.status, 'oracle');
});

test('classifyUniqueIndex: unique key INCLUDING the tenant column -> safe', () => {
  const v = classifyUniqueIndex({ columns: ['organization_id', 'email'], types: ['text', 'text'], tenantColumn: 'organization_id' });
  assert.equal(v.status, 'safe');
});

test('classifyUniqueIndex: primary keys are skipped (globally unique by design)', () => {
  const v = classifyUniqueIndex({ isPrimary: true, columns: ['id'], types: ['integer'], tenantColumn: 'organization_id' });
  assert.equal(v.status, 'skip');
  assert.match(v.reason, /primary key/);
});

test('classifyUniqueIndex: a single UUID column is skipped — unguessable, so not a practical oracle', () => {
  const v = classifyUniqueIndex({ columns: ['external_ref'], types: ['uuid'], tenantColumn: 'organization_id' });
  assert.equal(v.status, 'skip');
  assert.match(v.reason, /unguessable/);
  // ...but a uuid PAIRED with a guessable column is still an oracle
  assert.equal(classifyUniqueIndex({ columns: ['external_ref', 'email'], types: ['uuid', 'text'], tenantColumn: 'organization_id' }).status, 'oracle');
});

test('classifyUniqueIndex: a table with no tenant column is not tenant-scoped data', () => {
  const v = classifyUniqueIndex({ columns: ['name'], types: ['text'], tenantColumn: null });
  assert.equal(v.status, 'skip');
  assert.match(v.reason, /no tenant column/);
});

test('classifyUniqueIndex: expression indexes are skipped, not guessed at', () => {
  assert.equal(classifyUniqueIndex({ hasExpression: true, columns: [null], types: [null], tenantColumn: 'organization_id' }).status, 'skip');
  // a null slipping into the column list means the same thing
  assert.equal(classifyUniqueIndex({ columns: [null], types: [null], tenantColumn: 'organization_id' }).status, 'skip');
});

test('classifyForeignKey: single-column FK between two tenant tables -> oracle', () => {
  const v = classifyForeignKey({ columns: ['author'], childTenantColumn: 'organization_id', parentTenantColumn: 'organization_id' });
  assert.equal(v.status, 'oracle');
});

test('classifyForeignKey: a composite FK carrying the tenant -> safe', () => {
  const v = classifyForeignKey({ columns: ['organization_id', 'author'], childTenantColumn: 'organization_id', parentTenantColumn: 'organization_id' });
  assert.equal(v.status, 'safe');
});

test('classifyForeignKey: skipped unless BOTH ends are tenant-scoped', () => {
  assert.equal(classifyForeignKey({ columns: ['country'], childTenantColumn: 'organization_id', parentTenantColumn: null }).status, 'skip');
  assert.equal(classifyForeignKey({ columns: ['x'], childTenantColumn: null, parentTenantColumn: 'organization_id' }).status, 'skip');
});
