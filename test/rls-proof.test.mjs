/**
 * rls-proof pure-logic tests. Zero dependencies — the SQL builders, the table
 * planner, and the verdict logic are all I/O-free and testable without a
 * database. The end-to-end proof (against a real Postgres) lives in
 * rls-proof.integration.test.mjs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  quoteIdent,
  qualified,
  safeRole,
  introspectionSql,
  planTables,
  distinctTenantsSql,
  tenantRowCountSql,
  tenantCountsSql,
  updateProbeSql,
  deleteProbeSql,
  insertProbeSql,
  buildBecomeTenant,
  isPermissionDenied,
  isRlsCheckViolation,
  classifyTableResult,
  run,
  DEFAULTS,
} from '../src/guards/rls-proof.mjs';

// ── identifier / role safety ─────────────────────────────────────────
test('quoteIdent: quotes and escapes, rejects empty / NUL', () => {
  assert.equal(quoteIdent('invoices'), '"invoices"');
  assert.equal(quoteIdent('weird"name'), '"weird""name"'); // doubled quote
  assert.equal(qualified('public', 'invoices'), '"public"."invoices"');
  assert.throws(() => quoteIdent(''));
  assert.throws(() => quoteIdent('a\0b'));
});

test('safeRole: accepts identifiers, rejects injection', () => {
  assert.equal(safeRole('authenticated'), 'authenticated');
  assert.throws(() => safeRole('authenticated; drop table x'));
  assert.throws(() => safeRole('has space'));
});

// ── SQL builders carry params, never interpolate values ──────────────
test('introspectionSql: parameterises schemas + columns, asks for RLS status', () => {
  const { text, values } = introspectionSql(['public'], ['organization_id']);
  assert.deepEqual(values, [['public'], ['organization_id']]);
  assert.match(text, /relrowsecurity/);
  assert.match(text, /\$1/);
  assert.match(text, /\$2/);
});

test('distinctTenantsSql / tenantRowCountSql: quote idents, bind values, cast to text', () => {
  const d = distinctTenantsSql('public', 'invoices', 'organization_id', 3);
  assert.match(d.text, /from "public"\."invoices"/);
  assert.match(d.text, /"organization_id"::text/);
  assert.deepEqual(d.values, [3]);

  const c = tenantRowCountSql('public', 'invoices', 'organization_id', 'org_B');
  assert.match(c.text, /count\(\*\)/);
  assert.match(c.text, /"organization_id"::text = \$1/);
  assert.deepEqual(c.values, ['org_B']); // value bound, not interpolated
});

test('introspectionSql: also asks for a per-table policy count (to catch RLS-on-no-policy)', () => {
  const { text } = introspectionSql(['public'], ['organization_id']);
  assert.match(text, /pg_policy/);
  assert.match(text, /policy_count/);
});

test('planTables: carries the policy count through', () => {
  const rows = [{ schema: 'public', table: 't', column: 'organization_id', rls_enabled: true, rls_forced: false, policy_count: 0 }];
  const plan = planTables(rows, ['organization_id']);
  assert.equal(plan[0].policyCount, 0);
});

test('write probes: whole-table UPDATE/DELETE with NO WHERE (to dodge SELECT masking)', () => {
  const u = updateProbeSql('public', 'invoices', 'organization_id', 'org_A');
  assert.match(u.text, /^update "public"\."invoices" set "organization_id" = \$1$/);
  assert.deepEqual(u.values, ['org_A']); // sets the tenant column to the ACTING tenant (steal probe)
  assert.doesNotMatch(u.text, /where/i); // a WHERE would be masked by a correct read policy

  const d = deleteProbeSql('public', 'invoices');
  assert.match(d.text, /^delete from "public"\."invoices"$/);
  assert.deepEqual(d.values, []);
  assert.doesNotMatch(d.text, /where/i);
});

test('insertProbeSql: inserts a row for the OTHER tenant, NO returning (RETURNING masks the leak)', () => {
  const i = insertProbeSql('public', 'invoices', 'organization_id', 'org_B');
  assert.match(i.text, /^insert into "public"\."invoices" \("organization_id"\) values \(\$1\)$/);
  assert.doesNotMatch(i.text, /returning/i); // RETURNING re-applies the SELECT policy and hides the very leak we hunt
  assert.deepEqual(i.values, ['org_B']); // the OTHER tenant — a row that lands here is a cross-tenant insert
});

test('isRlsCheckViolation: matches a WITH CHECK block, NOT a NOT NULL/constraint error (which is inconclusive)', () => {
  assert.equal(isRlsCheckViolation({ code: '42501', message: 'new row violates row-level security policy for table "invoices"' }), true);
  assert.equal(isRlsCheckViolation({ code: '23502', message: 'null value in column "body" violates not-null constraint' }), false);
  assert.equal(isRlsCheckViolation({ code: '42501', message: 'permission denied for table invoices' }), false); // no grant ≠ WITH CHECK block
});

test('tenantCountsSql: privileged per-tenant counts, bound as $1/$2', () => {
  const c = tenantCountsSql('public', 'invoices', 'organization_id', 'org_A', 'org_B');
  assert.match(c.text, /own_a/);
  assert.match(c.text, /own_b/);
  assert.match(c.text, /"organization_id"::text = \$1/);
  assert.deepEqual(c.values, ['org_A', 'org_B']);
});

test('isPermissionDenied: also treats a WITH CHECK violation (blocked write) as blocked/safe', () => {
  assert.equal(isPermissionDenied({ message: 'new row violates row-level security policy for table "invoices"' }), true);
});

test('buildBecomeTenant: one statement per template, tenant id bound as $1', () => {
  const stmts = buildBecomeTenant(DEFAULTS.becomeTenant, 'org_A');
  assert.equal(stmts.length, 1);
  assert.match(stmts[0].text, /set_config\('app\.current_tenant', \$1, true\)/);
  assert.deepEqual(stmts[0].values, ['org_A']);
});

// ── table planner ────────────────────────────────────────────────────
test('planTables: picks the highest-priority tenant column, reads RLS flags', () => {
  const rows = [
    { schema: 'public', table: 'invoices', column: 'tenant_id', rls_enabled: true, rls_forced: false },
    { schema: 'public', table: 'invoices', column: 'organization_id', rls_enabled: true, rls_forced: false },
  ];
  const cols = ['organization_id', 'tenant_id'];
  const plan = planTables(rows, cols);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].tenantColumn, 'organization_id'); // priority beats tenant_id
  assert.equal(plan[0].rlsEnabled, true);
});

test('planTables: honours grandfather (by name and schema.table), tolerates char RLS flags', () => {
  const rows = [
    { schema: 'public', table: 'invoices', column: 'organization_id', rls_enabled: 't', rls_forced: 'f' },
    { schema: 'public', table: 'shared_lookup', column: 'organization_id', rls_enabled: 'f', rls_forced: 'f' },
  ];
  const plan = planTables(rows, ['organization_id'], ['shared_lookup']);
  assert.equal(plan.length, 1);
  assert.equal(plan[0].table, 'invoices');
  assert.equal(plan[0].rlsEnabled, true); // 't' coerced
});

// ── error classification ─────────────────────────────────────────────
test('isPermissionDenied: matches SQLSTATE 42501 and the message', () => {
  assert.equal(isPermissionDenied({ code: '42501' }), true);
  assert.equal(isPermissionDenied({ message: 'permission denied for table invoices' }), true);
  assert.equal(isPermissionDenied({ code: '23505' }), false);
  assert.equal(isPermissionDenied(null), false);
});

// ── the verdict logic (the heart of the guard) ───────────────────────
test('classify: sees own rows, none of the other tenant -> isolated (pass)', () => {
  const v = classifyTableResult({ rlsEnabled: true, ownVisible: 5, crossVisible: 0, tenantCount: 2 });
  assert.equal(v.status, 'isolated');
});

test('classify: READS the other tenant with RLS on -> read leak (permissive policy)', () => {
  const v = classifyTableResult({ rlsEnabled: true, ownVisible: 5, crossVisible: 3, tenantCount: 2 });
  assert.equal(v.status, 'leak');
  assert.equal(v.leaks.length, 1);
  assert.equal(v.leaks[0].kind, 'read');
  assert.match(v.leaks[0].message, /permissive or missing the tenant predicate/);
  assert.match(v.leaks[0].fix, /current_setting/);
});

test('classify: READS the other tenant with RLS off -> read leak (RLS disabled = the CVE case)', () => {
  const v = classifyTableResult({ rlsEnabled: false, ownVisible: 5, crossVisible: 3, tenantCount: 2 });
  assert.equal(v.status, 'leak');
  assert.equal(v.leaks[0].kind, 'read');
  assert.match(v.leaks[0].message, /ROW LEVEL SECURITY is not enabled/);
  assert.match(v.leaks[0].fix, /ENABLE ROW LEVEL SECURITY/);
});

test('classify: WRITES the other tenant (reads clean) -> write leak (per-command RLS gap)', () => {
  const v = classifyTableResult({ rlsEnabled: true, ownVisible: 5, crossVisible: 0, writeAffected: 2, tenantCount: 2, probedWrites: true });
  assert.equal(v.status, 'leak');
  assert.equal(v.leaks.length, 1);
  assert.equal(v.leaks[0].kind, 'write');
  assert.match(v.leaks[0].message, /cross-tenant WRITE affecting 2 row/);
  assert.match(v.leaks[0].fix, /FOR ALL|WITH CHECK/);
});

test('classify: INSERTs into the other tenant (reads + update/delete clean) -> write leak (INSERT WITH CHECK gap)', () => {
  const v = classifyTableResult({ rlsEnabled: true, ownVisible: 5, crossVisible: 0, writeAffected: 0, insertLeaked: true, tenantCount: 2, probedWrites: true });
  assert.equal(v.status, 'leak');
  assert.equal(v.leaks.length, 1);
  assert.equal(v.leaks[0].kind, 'write');
  assert.match(v.leaks[0].message, /INSERTed a row belonging to tenant B|CREATE rows in another tenant/);
  assert.match(v.leaks[0].fix, /WITH CHECK/);
});

test('classify: reads AND writes the other tenant -> two leaks (read + write)', () => {
  const v = classifyTableResult({ rlsEnabled: true, ownVisible: 5, crossVisible: 3, writeAffected: 1, tenantCount: 2, probedWrites: true });
  assert.equal(v.status, 'leak');
  assert.deepEqual(v.leaks.map((l) => l.kind).sort(), ['read', 'write']);
});

test('classify: RLS enabled but zero policies -> no-policy (deny-all that only looks isolated)', () => {
  const v = classifyTableResult({ rlsEnabled: true, policyCount: 0, ownVisible: 0, crossVisible: 0, tenantCount: 2 });
  assert.equal(v.status, 'no-policy');
  assert.match(v.message, /NO policy/);
});

test('classify: no-access takes precedence over no-policy (can\'t even SELECT)', () => {
  const v = classifyTableResult({ noAccess: true, rlsEnabled: true, policyCount: 0, tenantCount: 2, ownVisible: 0, crossVisible: 0 });
  assert.equal(v.status, 'no-access');
});

test('classify: fewer than two tenants -> insufficient-data (not a failure)', () => {
  const v = classifyTableResult({ rlsEnabled: true, ownVisible: 0, crossVisible: 0, tenantCount: 1 });
  assert.equal(v.status, 'insufficient-data');
});

test('classify: sees nothing at all -> over-restrictive (config smell, not a leak)', () => {
  const v = classifyTableResult({ rlsEnabled: true, ownVisible: 0, crossVisible: 0, tenantCount: 2 });
  assert.equal(v.status, 'over-restrictive');
});

test('classify: no SELECT grant -> no-access (safe, nothing to prove)', () => {
  const v = classifyTableResult({ noAccess: true, tenantCount: 2, ownVisible: 0, crossVisible: 0 });
  assert.equal(v.status, 'no-access');
});

// ── run() wrapper: skips cleanly with no database (a skip is never a pass) ────
test('run: with no database URL configured, skips (ok, does not fail the build)', async () => {
  const saved = { a: process.env.TENANT_GUARD_DATABASE_URL, b: process.env.DATABASE_URL };
  delete process.env.TENANT_GUARD_DATABASE_URL;
  delete process.env.DATABASE_URL;
  try {
    const res = await run({ urlEnv: 'TENANT_GUARD_DATABASE_URL' });
    assert.equal(res.ok, true);
    assert.equal(res.skipped, true);
    assert.match(res.reason, /no database configured/);
    assert.equal(res.id, 'rls-proof');
  } finally {
    if (saved.a !== undefined) process.env.TENANT_GUARD_DATABASE_URL = saved.a;
    if (saved.b !== undefined) process.env.DATABASE_URL = saved.b;
  }
});
