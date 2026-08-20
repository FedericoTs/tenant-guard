/**
 * definer-rpc pure-logic tests. The volatility rule is the safety-critical one:
 * it is what decides whether tenant-guard is willing to CALL a function at all.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  definerRpcSql,
  isReadOnlyVolatility,
  bodyConsultsIdentity,
  bodyTouchesTenantTable,
  planCall,
  noArgProbeSql,
  tenantArgProbeSql,
  classifyRpc,
} from '../src/guards/definer-rpc.mjs';

test('definerRpcSql: only SECURITY DEFINER, excludes triggers, reads volatility + EXECUTE grant', () => {
  const { text, values } = definerRpcSql(['public'], 'authenticated');
  assert.match(text, /prosecdef/);
  assert.match(text, /provolatile/);
  assert.match(text, /has_function_privilege/);
  assert.match(text, /<> 'trigger'/); // trigger functions aren't callable RPCs
  assert.deepEqual(values, [['public'], 'authenticated']);
});

test('isReadOnlyVolatility: ONLY stable/immutable are safe to call', () => {
  // Postgres enforces this: "INSERT is not allowed in a non-volatile function".
  assert.equal(isReadOnlyVolatility('s'), true);  // STABLE
  assert.equal(isReadOnlyVolatility('i'), true);  // IMMUTABLE
  assert.equal(isReadOnlyVolatility('v'), false); // VOLATILE — may write, never called
  assert.equal(isReadOnlyVolatility(undefined), false);
});

test('bodyConsultsIdentity: recognises the ways a body can scope by the caller', () => {
  assert.equal(bodyConsultsIdentity(`select * from t where user_id = auth.uid()`), true);
  assert.equal(bodyConsultsIdentity(`select current_setting('app.current_tenant', true)`), true);
  assert.equal(bodyConsultsIdentity(`select (auth.jwt() ->> 'org_id')`), true);
  assert.equal(bodyConsultsIdentity(`select * from invoices`), false);
  assert.equal(bodyConsultsIdentity(null), false);
});

test('bodyTouchesTenantTable: word-boundary match against known tenant tables', () => {
  assert.equal(bodyTouchesTenantTable('select * from invoices', ['invoices']), true);
  assert.equal(bodyTouchesTenantTable('select * from invoices_archive', ['invoices']), false);
  assert.equal(bodyTouchesTenantTable('select 1', ['invoices']), false);
  assert.equal(bodyTouchesTenantTable(null, ['invoices']), false);
});

test('planCall: zero args -> callable; one tenant-shaped arg -> callable with a tenant id', () => {
  assert.equal(planCall({ nargs: 0 }).mode, 'no-args');
  assert.equal(planCall({ nargs: 1, argTypes: ['text'] }).mode, 'tenant-arg');
  assert.equal(planCall({ nargs: 1, argTypes: ['uuid'] }).mode, 'tenant-arg');
});

test('planCall: skips rather than inventing values it cannot justify', () => {
  const notTenantShaped = planCall({ nargs: 1, argTypes: ['integer'] });
  assert.equal(notTenantShaped.mode, 'skip');
  assert.match(notTenantShaped.reason, /not a tenant-shaped type/);

  const many = planCall({ nargs: 3, argTypes: ['text', 'text', 'integer'] });
  assert.equal(many.mode, 'skip');
  assert.match(many.reason, /won't invent values/);
});

test('probe SQL: quotes identifiers and binds the tenant id, never interpolates it', () => {
  assert.match(noArgProbeSql('public', 'all_invoices', 'organization_id').text,
    /from "public"\."all_invoices"\(\) x where x\."organization_id"::text <> \$1/);
  assert.match(tenantArgProbeSql('public', 'get_invoices', 'text').text,
    /from "public"\."get_invoices"\(\$1::text\) x/);
  // an argument type outside the allowlist is refused rather than interpolated
  assert.throws(() => tenantArgProbeSql('public', 'f', 'text); drop table x --'));
});

test('classify: a VOLATILE function is never a leak verdict — only an unproven note', () => {
  const v = classifyRpc({
    schema: 'public', name: 'f', volatility: 'v', canExecute: true,
    touchesTenantTable: true, consultsIdentity: false,
  });
  assert.equal(v.status, 'note');
  assert.match(v.message, /NOT PROVEN/);
  assert.match(v.message, /rollback cannot undo/);
});

test('classify: a VOLATILE function that DOES consult identity is not even noted', () => {
  const v = classifyRpc({
    schema: 'public', name: 'f', volatility: 'v', canExecute: true,
    touchesTenantTable: true, consultsIdentity: true,
  });
  assert.equal(v.status, 'skip');
});

test('classify: foreign rows from a tenant-arg call -> trusts-argument leak', () => {
  const v = classifyRpc({
    schema: 'public', name: 'get_invoices', args: 'org text', volatility: 's', canExecute: true,
    mode: 'tenant-arg', foreignRows: 2, controlRows: 0,
  });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'trusts-argument');
  assert.match(v.fix, /REVOKE EXECUTE/);
});

test('classify: rows for a NONEXISTENT tenant too -> reclassified as no-filter', () => {
  const v = classifyRpc({
    schema: 'public', name: 'sloppy', volatility: 's', canExecute: true,
    mode: 'tenant-arg', foreignRows: 3, controlRows: 3,
  });
  assert.equal(v.kind, 'no-filter'); // the control arm changes the diagnosis
});

test('classify: no EXECUTE grant -> skipped, never a finding', () => {
  assert.equal(classifyRpc({ schema: 'public', name: 'f', volatility: 's', canExecute: false }).status, 'skip');
});

test('classify: zero foreign rows -> safe', () => {
  assert.equal(classifyRpc({ schema: 'public', name: 'f', volatility: 's', canExecute: true, mode: 'no-args', foreignRows: 0 }).status, 'safe');
});
