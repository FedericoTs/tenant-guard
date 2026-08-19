/**
 * identity-trust pure-logic tests: the policy-expression classifier, the definer
 * body analyser, and the claim-key derivation are all I/O-free.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  policyExprSql,
  classifyIdentitySource,
  classifyPolicyRow,
  definerFunctionsSql,
  parameterNames,
  definerSetsTrustedGuc,
  forgeUserMetadataSql,
  deriveClaimKey,
  authorityDepsSql,
  effectiveCheck,
  classifyAuthority,
} from '../src/guards/identity-trust.mjs';

test('policyExprSql: scopes to tenant-column tables, parameterised', () => {
  const { text, values } = policyExprSql(['public'], ['organization_id']);
  assert.match(text, /pg_policies/);
  assert.match(text, /qual/);
  assert.match(text, /with_check/);
  assert.deepEqual(values, [['public'], ['organization_id']]);
});

test('classifyIdentitySource: spots user_metadata (both Supabase spellings)', () => {
  assert.equal(classifyIdentitySource(`(org_id = (auth.jwt() -> 'user_metadata' ->> 'org_id'))`).usesUserMetadata, true);
  assert.equal(classifyIdentitySource(`(org_id = (u.raw_user_meta_data ->> 'org_id'))`).usesUserMetadata, true);
  assert.equal(classifyIdentitySource(`(org_id = (auth.jwt() -> 'app_metadata' ->> 'org_id'))`).usesUserMetadata, false);
});

test('classifyIdentitySource: app_metadata and JWT use are recognised as the safe sources', () => {
  const c = classifyIdentitySource(`(org_id = (auth.jwt() -> 'app_metadata' ->> 'org_id'))`);
  assert.equal(c.usesAppMetadata, true);
  assert.equal(c.usesJwt, true);
  assert.deepEqual(c.settableGucs, []);
});

test('classifyIdentitySource: collects settable GUCs but EXCLUDES request.jwt.* (PostgREST sets those from a verified token)', () => {
  const c = classifyIdentitySource(`(org_id = current_setting('app.current_tenant'::text, true))`);
  assert.deepEqual(c.settableGucs, ['app.current_tenant']);

  const jwt = classifyIdentitySource(`(org_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id'))`);
  assert.deepEqual(jwt.settableGucs, []); // not client-settable in the architecture that uses it
  assert.equal(jwt.usesJwt, true);
});

test('classifyIdentitySource: tolerates null/empty expressions (a policy may have no with_check)', () => {
  const c = classifyIdentitySource(null);
  assert.equal(c.usesUserMetadata, false);
  assert.deepEqual(c.settableGucs, []);
});

test('classifyPolicyRow: merges qual AND with_check — a leak in either counts', () => {
  const row = {
    schema: 'public', table: 't', policy: 'p', cmd: 'ALL',
    qual: `(org_id = current_setting('app.tenant'))`,
    with_check: `(org_id = (auth.jwt() -> 'user_metadata' ->> 'org_id'))`,
  };
  const c = classifyPolicyRow(row);
  assert.equal(c.usesUserMetadata, true);       // found only in with_check
  assert.deepEqual(c.settableGucs, ['app.tenant']); // found only in qual
  assert.equal(c.id, 'public.t');
});

test('definerFunctionsSql: only SECURITY DEFINER, asks for body + EXECUTE grant', () => {
  const { text, values } = definerFunctionsSql(['public'], 'authenticated');
  assert.match(text, /prosecdef/);
  assert.match(text, /has_function_privilege/);
  assert.match(text, /prosrc/);
  assert.deepEqual(values, [['public'], 'authenticated']);
});

test('parameterNames: extracts declared names, ignores modes and unnamed args', () => {
  assert.deepEqual(parameterNames('target text, other integer'), ['target', 'other']);
  assert.deepEqual(parameterNames('IN target text'), ['target']);
  assert.deepEqual(parameterNames('text, integer'), []); // unnamed — nothing to match on
  assert.deepEqual(parameterNames(null), []);
});

test('definerSetsTrustedGuc: fromParam=true when the value comes from an ARGUMENT (the escalation)', () => {
  const hit = definerSetsTrustedGuc(
    `begin perform set_config('app.current_tenant', target, true); end`,
    'target text',
    ['app.current_tenant'],
  );
  assert.ok(hit);
  assert.equal(hit.guc, 'app.current_tenant');
  assert.equal(hit.fromParam, true);
});

test('definerSetsTrustedGuc: fromParam=false when derived from the SESSION (legitimate)', () => {
  const hit = definerSetsTrustedGuc(
    `begin perform set_config('app.current_tenant', (current_setting('request.jwt.claims', true)::json ->> 'org_id'), true); end`,
    '',
    ['app.current_tenant'],
  );
  assert.ok(hit);
  assert.equal(hit.fromParam, false);
});

test('definerSetsTrustedGuc: positional $1 also counts as caller-supplied', () => {
  const hit = definerSetsTrustedGuc(`select set_config('app.tenant', $1, true)`, '', ['app.tenant']);
  assert.equal(hit.fromParam, true);
});

test('definerSetsTrustedGuc: ignores functions that set some OTHER guc', () => {
  assert.equal(definerSetsTrustedGuc(`perform set_config('app.locale', target, true);`, 'target text', ['app.current_tenant']), null);
  assert.equal(definerSetsTrustedGuc('', 'x text', ['app.tenant']), null);
  assert.equal(definerSetsTrustedGuc('body', 'x text', []), null);
});

test('forgeUserMetadataSql: nests the key under user_metadata ONLY, and rejects an unsafe key', () => {
  const sql = forgeUserMetadataSql('org_id');
  assert.match(sql, /'user_metadata'/);
  assert.match(sql, /json_build_object\('org_id', \$1::text\)/);
  // The top-level claim is deliberately absent: a policy reading the top-level
  // key must get NULL, so a positive result can only mean user_metadata was trusted.
  assert.doesNotMatch(sql, /json_build_object\('org_id'[^)]*\)\s*::text\s*,\s*true/);
  assert.throws(() => forgeUserMetadataSql(`org_id'); drop table x --`));
});

test('deriveClaimKey: prefers the explicit claim, then the becomeTenant template, then the column', () => {
  assert.equal(deriveClaimKey({ claim: 'team_id' }, 'organization_id'), 'team_id');
  assert.equal(deriveClaimKey({ claim: { key: 'account_id' } }, 'organization_id'), 'account_id');
  assert.equal(
    deriveClaimKey({ becomeTenant: [`select set_config('request.jwt.claims', json_build_object('org_id', $1::text)::text, true)`] }, 'organization_id'),
    'org_id',
  );
  assert.equal(deriveClaimKey({ becomeTenant: [`select set_config('app.current_tenant', $1, true)`] }, 'organization_id'), 'organization_id');
});

// ── authority tables (threat-model 2.10) ─────────────────────────────

test('authorityDepsSql: reads policy dependencies from pg_depend and excludes the policy\'s own table', () => {
  const { text, values } = authorityDepsSql(['public']);
  assert.match(text, /pg_depend/);
  assert.match(text, /pg_policy/);
  assert.match(text, /dc\.oid <> p\.polrelid/); // self-dependency excluded
  assert.deepEqual(values, [['public']]);
});

test('effectiveCheck: FOR ALL with no WITH CHECK falls back to USING; FOR INSERT does not', () => {
  assert.equal(effectiveCheck({ cmd: 'ALL', qual: 'q', with_check: null }), 'q');
  assert.equal(effectiveCheck({ cmd: 'ALL', qual: 'q', with_check: 'wc' }), 'wc');
  assert.equal(effectiveCheck({ cmd: 'INSERT', qual: null, with_check: 'wc' }), 'wc');
  assert.equal(effectiveCheck({ cmd: 'UPDATE', qual: 'q', with_check: null }), null);
});

test('classifyAuthority: RLS off + write grant -> leak (structural, conclusive)', () => {
  const v = classifyAuthority({ schema: 'public', table: 'memberships', tenantColumn: 'organization_id', rlsEnabled: false, canInsert: true, dependents: ['public.invoices'] });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /RLS is OFF/);
});

test('classifyAuthority: a check that omits the tenant column -> leak (the user_id = auth.uid() near-miss)', () => {
  const v = classifyAuthority({
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true,
    writePolicies: [{ policy: 'self', cmd: 'INSERT', with_check: '(user_id = auth.uid())' }],
  });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /never constrains "organization_id"/);
});

test('classifyAuthority: a check that DOES constrain the tenant column -> safe', () => {
  const v = classifyAuthority({
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true,
    writePolicies: [{ policy: 'scoped', cmd: 'INSERT', with_check: `(user_id = auth.uid() AND organization_id = current_setting('app.tenant'))` }],
  });
  assert.equal(v.status, 'safe');
});

test('classifyAuthority: RLS on with no write policy -> safe (writes are denied outright)', () => {
  const v = classifyAuthority({
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true,
    writePolicies: [{ policy: 'read_own', cmd: 'SELECT', qual: 'x' }],
  });
  assert.equal(v.status, 'safe');
});

test('classifyAuthority: no write grant -> safe whatever the policies say', () => {
  const v = classifyAuthority({ schema: 'public', table: 'memberships', tenantColumn: 'organization_id', rlsEnabled: false, canInsert: false, canUpdate: false });
  assert.equal(v.status, 'safe');
});

test('classifyAuthority: writable but no tenant column -> unknown (a note, never a silent pass)', () => {
  const v = classifyAuthority({ schema: 'public', table: 'admin_flags', tenantColumn: null, rlsEnabled: false, canInsert: true, dependents: ['public.invoices'] });
  assert.equal(v.status, 'unknown');
  assert.match(v.message, /no recognised tenant column/);
});
