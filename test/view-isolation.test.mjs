/**
 * view-isolation pure-logic tests. The catalog query, the reloptions parser, the
 * planner, the verdict, and the fix-selection are all I/O-free.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  viewIntrospectionSql,
  hasSecurityInvoker,
  planViews,
  classifyViewResult,
  fixForView,
} from '../src/guards/view-isolation.mjs';

test('viewIntrospectionSql: views AND matviews only, parameterised, reads owner + reloptions', () => {
  const { text, values } = viewIntrospectionSql(['public'], ['organization_id']);
  assert.match(text, /relkind in \('v', 'm'\)/);
  assert.match(text, /relowner::regrole::text/);
  assert.match(text, /reloptions/);
  assert.deepEqual(values, [['public'], ['organization_id']]);
});

test('hasSecurityInvoker: parses the reloptions string, tolerates absent/odd forms', () => {
  assert.equal(hasSecurityInvoker('security_invoker=true'), true);
  assert.equal(hasSecurityInvoker('security_invoker=on'), true);
  assert.equal(hasSecurityInvoker('check_option=local,security_invoker=true'), true);
  assert.equal(hasSecurityInvoker('security_invoker=false'), false);
  assert.equal(hasSecurityInvoker(null), false);
  assert.equal(hasSecurityInvoker(''), false);
});

test('planViews: maps relkind to a kind, picks the priority tenant column, carries owner + invoker', () => {
  const rows = [
    { schema: 'public', view: 'v1', kind: 'v', column: 'tenant_id', owner_role: 'postgres', reloptions: null },
    { schema: 'public', view: 'v1', kind: 'v', column: 'organization_id', owner_role: 'postgres', reloptions: null },
    { schema: 'public', view: 'm1', kind: 'm', column: 'organization_id', owner_role: 'postgres', reloptions: null },
  ];
  const plan = planViews(rows, ['organization_id', 'tenant_id']);
  assert.equal(plan.length, 2);
  const v1 = plan.find((p) => p.view === 'v1');
  assert.equal(v1.kind, 'view');
  assert.equal(v1.tenantColumn, 'organization_id'); // priority beats tenant_id
  assert.equal(v1.securityInvoker, false);
  assert.equal(v1.ownerRole, 'postgres');
  assert.equal(plan.find((p) => p.view === 'm1').kind, 'matview');
});

test('planViews: honours the allowlist by bare name and schema.view', () => {
  const rows = [
    { schema: 'public', view: 'keep', kind: 'v', column: 'organization_id', owner_role: 'postgres', reloptions: null },
    { schema: 'public', view: 'drop_me', kind: 'v', column: 'organization_id', owner_role: 'postgres', reloptions: null },
  ];
  assert.equal(planViews(rows, ['organization_id'], ['drop_me']).length, 1);
  assert.equal(planViews(rows, ['organization_id'], ['public.drop_me']).length, 1);
});

test('classify: cross-tenant rows through a plain view -> leak naming the OWNER mechanism', () => {
  const v = classifyViewResult({ kind: 'view', securityInvoker: false, ownerRole: 'postgres', ownVisible: 2, crossVisible: 3, tenantCount: 2, schema: 'public', view: 'v' });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /does not set security_invoker/);
  assert.match(v.message, /"postgres"/);
});

test('classify: cross-tenant rows through a matview -> leak naming that RLS never applies', () => {
  const v = classifyViewResult({ kind: 'matview', ownerRole: 'postgres', ownVisible: 1, crossVisible: 1, tenantCount: 2, schema: 'public', view: 'm' });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /MATERIALIZED VIEW/);
  assert.match(v.message, /NEVER applies/i);
});

test('classify: a security_invoker view that still leaks blames the underlying table', () => {
  const v = classifyViewResult({ kind: 'view', securityInvoker: true, ownerRole: 'postgres', ownVisible: 2, crossVisible: 2, tenantCount: 2, schema: 'public', view: 'v' });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /IS security_invoker/);
  assert.match(v.fix, /tenant-guard prove/);
});

test('classify: sees own rows and none of the other tenant -> isolated', () => {
  assert.equal(classifyViewResult({ kind: 'view', ownVisible: 2, crossVisible: 0, tenantCount: 2 }).status, 'isolated');
});

test('classify: no SELECT grant -> no-access (nothing exposed, not a leak)', () => {
  const v = classifyViewResult({ kind: 'view', noAccess: true, tenantCount: 2, ownVisible: 0, crossVisible: 0 });
  assert.equal(v.status, 'no-access');
});

test('classify: fewer than two tenants -> insufficient-data (never a pass)', () => {
  assert.equal(classifyViewResult({ kind: 'view', tenantCount: 1, ownVisible: 0, crossVisible: 0 }).status, 'insufficient-data');
});

test('classify: sees nothing at all -> over-restrictive (config smell, not a leak)', () => {
  assert.equal(classifyViewResult({ kind: 'view', tenantCount: 2, ownVisible: 0, crossVisible: 0 }).status, 'over-restrictive');
});

test('fixForView: a matview never suggests security_invoker; a pre-PG15 view says so', () => {
  const mv = fixForView({ kind: 'matview', schema: 'public', view: 'm', role: 'authenticated' });
  assert.match(mv, /CANNOT be scoped by RLS/i);
  assert.doesNotMatch(mv, /ALTER VIEW/);

  const old = fixForView({ kind: 'view', schema: 'public', view: 'v', securityInvoker: false, role: 'authenticated', pgVersionNum: 140000 });
  assert.match(old, /predates security_invoker/);

  const modern = fixForView({ kind: 'view', schema: 'public', view: 'v', securityInvoker: false, role: 'authenticated', pgVersionNum: 160000 });
  assert.match(modern, /ALTER VIEW "public"\."v" SET \(security_invoker = true\)/);
});
