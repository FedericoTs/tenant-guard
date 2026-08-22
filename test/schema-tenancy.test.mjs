/**
 * schema-tenancy pure logic. Inference carries the false-positive risk — an
 * ordinary multi-schema database must never be mistaken for schema-per-tenant —
 * so that gets the most attention.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  schemaShapesSql,
  schemaUsageSql,
  schemaProbeSql,
  inferTenantSchemas,
  classifySchemaReach,
} from '../src/guards/schema-tenancy.mjs';

test('schemaShapesSql / schemaUsageSql / schemaProbeSql: catalog reads and a quoted probe', () => {
  assert.match(schemaShapesSql().text, /relkind in \('r', 'p'\)/);
  const u = schemaUsageSql(['tenant_a'], 'app_user');
  assert.match(u.text, /has_schema_privilege\(\$2::text/);
  assert.deepEqual(u.values, [['tenant_a'], 'app_user']);
  assert.match(schemaProbeSql('tenant_a', 'docs').text, /from "tenant_a"\."docs"/);
});

test('infer: two schemas holding the SAME tables is the schema-per-tenant signature', () => {
  const rows = [
    { schema: 'tenant_a', tables: ['docs', 'invoices'] },
    { schema: 'tenant_b', tables: ['invoices', 'docs'] }, // order must not matter
    { schema: 'public', tables: ['migrations'] },
  ];
  assert.deepEqual(inferTenantSchemas(rows), ['tenant_a', 'tenant_b']);
});

test('infer: an ordinary multi-schema database is NOT schema-per-tenant', () => {
  // Different schemas holding DIFFERENT things — the normal case, and the one a
  // naive "several schemas exist" check would false-flag.
  const rows = [
    { schema: 'public', tables: ['invoices'] },
    { schema: 'analytics', tables: ['rollups'] },
    { schema: 'audit', tables: ['events'] },
  ];
  assert.deepEqual(inferTenantSchemas(rows), []);
});

test('infer: system and Supabase schemas are never tenants, however they look', () => {
  const rows = [
    { schema: 'auth', tables: ['users'] },
    { schema: 'storage', tables: ['users'] }, // same shape, still not tenants
    { schema: 'public', tables: ['users'] },
  ];
  assert.deepEqual(inferTenantSchemas(rows), []);
});

test('infer: picks the LARGEST repeated group when several exist', () => {
  const rows = [
    { schema: 't1', tables: ['docs'] },
    { schema: 't2', tables: ['docs'] },
    { schema: 't3', tables: ['docs'] },
    { schema: 'x1', tables: ['other'] },
    { schema: 'x2', tables: ['other'] },
  ];
  assert.deepEqual(inferTenantSchemas(rows), ['t1', 't2', 't3']);
});

test('infer: a pattern overrides shape entirely (for irregular layouts)', () => {
  const rows = [
    { schema: 'org_123', tables: ['docs'] },
    { schema: 'org_456', tables: ['notes'] }, // different shape — inference alone would miss it
    { schema: 'analytics', tables: ['docs'] },
  ];
  assert.deepEqual(inferTenantSchemas(rows, { pattern: '^org_' }), ['org_123', 'org_456']);
});

test('infer: empty schemas are ignored (no tables is no signature)', () => {
  const rows = [{ schema: 'tenant_a', tables: [] }, { schema: 'tenant_b', tables: [] }];
  assert.deepEqual(inferTenantSchemas(rows), []);
});

test('classify: reaching two or more tenant schemas -> leak', () => {
  const v = classifySchemaReach({
    role: 'app_user',
    tenantSchemas: ['tenant_a', 'tenant_b'],
    reachable: ['tenant_a', 'tenant_b'],
    probed: [{ schema: 'tenant_a', table: 'docs', rows: 1 }, { schema: 'tenant_b', table: 'docs', rows: 1 }],
  });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /GRANTs are the entire boundary/);
  assert.match(v.message, /proven by reading from/);
  // The revoke has to name the grantees that HOLD the access. It used to say
  // `REVOKE ALL ON SCHEMA tenant_b FROM tenant_a_app` — the role the fix creates
  // one line earlier, which holds nothing, so it was inert in every case.
  // See test/schema-tenancy-audit.test.mjs for the measured proof.
  assert.match(v.fix, /REVOKE ALL ON SCHEMA tenant_a, tenant_b FROM PUBLIC, "app_user";/);
});

test('classify: reaching exactly one -> isolated (the correct per-tenant-role setup)', () => {
  assert.equal(classifySchemaReach({ reachable: ['tenant_a'], tenantSchemas: ['tenant_a', 'tenant_b'] }).status, 'isolated');
});

test('classify: reaching none -> no-access, not a leak', () => {
  const v = classifySchemaReach({ reachable: [], tenantSchemas: ['tenant_a', 'tenant_b'] });
  assert.equal(v.status, 'no-access');
  assert.match(v.message, /cannot reach any/);
});
